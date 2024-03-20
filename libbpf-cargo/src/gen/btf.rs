use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ops::Deref;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;

use libbpf_rs::btf::types;
use libbpf_rs::btf::BtfKind;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::btf_type_match;
use libbpf_rs::Btf;
use libbpf_rs::HasSize;
use libbpf_rs::ReferencesType;

use super::definition::DefinitionVisitor;
use super::visit::visit_type_hierarchy;

const ANON_PREFIX: &str = "__anon_";

/// Check whether the provided type is "unsafe" to use.
///
/// A type is considered unsafe by this function if it is not valid for
/// any bit pattern.
pub(crate) fn is_unsafe(ty: BtfType<'_>) -> bool {
    let ty = ty.skip_mods_and_typedefs();

    btf_type_match!(match ty {
        BtfKind::Int(t) => matches!(t.encoding, types::IntEncoding::Bool),
        BtfKind::Enum | BtfKind::Enum64 => true,
        _ => false,
    })
}

pub(crate) fn is_struct_packed(btf: &Btf<'_>, composite: &types::Composite<'_>) -> Result<bool> {
    if !composite.is_struct {
        return Ok(false);
    }

    let align = composite.alignment()?;

    // Size of a struct has to be a multiple of its alignment
    if composite.size() % align != 0 {
        return Ok(true);
    }

    // All the non-bitfield fields have to be naturally aligned
    for m in composite.iter() {
        let align = btf.type_by_id::<BtfType<'_>>(m.ty).unwrap().alignment()?;

        if let types::MemberAttr::Normal { offset } = m.attr {
            if offset as usize % (align.get() * 8) != 0 {
                return Ok(true);
            }
        }
    }

    // Even if original struct was marked as packed, we haven't detected any misalignment, so
    // there is no effect of packedness for given struct
    Ok(false)
}

/// Given a `current_offset` (in bytes) into a struct and a `required_offset` (in bytes) that
/// type `type_id` needs to be placed at, returns how much padding must be inserted before
/// `type_id`.
pub(crate) fn required_padding(
    current_offset: usize,
    required_offset: usize,
    ty: &BtfType<'_>,
    packed: bool,
) -> Result<usize> {
    ensure!(
        current_offset <= required_offset,
        "current offset ({current_offset}) ahead of required offset ({required_offset})"
    );

    let align = if packed {
        NonZeroUsize::new(1).unwrap()
    } else {
        // Assume 32-bit alignment in case we're generating code for 32-bit
        // arch. Worst case is on a 64-bit arch the compiler will generate
        // extra padding. The final layout will still be identical to what is
        // described by BTF.
        let a = ty.alignment()?;

        if a.get() > 4 {
            NonZeroUsize::new(4).unwrap()
        } else {
            a
        }
    };

    // If we aren't aligning to the natural offset, padding needs to be inserted
    let aligned_offset = (current_offset + align.get() - 1) / align * align.get();
    if aligned_offset == required_offset {
        Ok(0)
    } else {
        Ok(required_offset - current_offset)
    }
}

pub(crate) fn type_declaration(ty: BtfType<'_>, anon_types: &AnonTypes) -> Result<String> {
    let ty = ty.skip_mods_and_typedefs();

    let s = btf_type_match!(match ty {
        BtfKind::Void => "std::ffi::c_void".to_string(),
        BtfKind::Int(t) => {
            let width = match (t.bits + 7) / 8 {
                1 => "8",
                2 => "16",
                4 => "32",
                8 => "64",
                16 => "128",
                _ => bail!("Invalid integer width"),
            };

            match t.encoding {
                types::IntEncoding::Signed => format!("i{width}"),
                types::IntEncoding::Bool => {
                    assert!(t.bits as usize == (size_of::<bool>() * 8));
                    "bool".to_string()
                }
                types::IntEncoding::Char | types::IntEncoding::None => format!("u{width}"),
            }
        }
        BtfKind::Float(t) => {
            let width = match t.size() {
                2 => bail!("Unsupported float width"),
                4 => "32",
                8 => "64",
                12 => bail!("Unsupported float width"),
                16 => bail!("Unsupported float width"),
                _ => bail!("Invalid float width"),
            };

            format!("f{width}")
        }
        BtfKind::Ptr(t) => {
            let pointee_ty = type_declaration(t.referenced_type(), anon_types)?;

            format!("*mut {pointee_ty}")
        }
        BtfKind::Array(t) => {
            let val_ty = type_declaration(t.contained_type(), anon_types)?;

            format!("[{}; {}]", val_ty, t.capacity())
        }
        BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64 =>
            anon_types.type_name_or_anon(&ty).into_owned(),
        // The only way a variable references a function or forward declaration is through a
        // pointer. Return c_void here so the final def will look like `*mut c_void`.
        //
        // It's not like rust code can call a function inside a bpf prog either so we don't
        // really need a full definition. `void *` is totally sufficient for sharing a pointer.
        BtfKind::Fwd | BtfKind::Func | BtfKind::FuncProto => "std::ffi::c_void".to_string(),
        BtfKind::Var(t) => type_declaration(t.referenced_type(), anon_types)?,
        _ => bail!("Invalid type: {ty:?}"),
    });
    Ok(s)
}

/// Returns an expression that evaluates to the Default value
/// of a type(typeid) in string form.
///
/// To be used when creating a impl Default for a structure
///
/// Rule of thumb is `ty` must be a type a variable can have.
///
/// Type qualifiers are discarded (eg `const`, `volatile`, etc).
pub(crate) fn type_default(ty: BtfType<'_>, anon_types: &AnonTypes) -> Result<String> {
    let ty = ty.skip_mods_and_typedefs();

    Ok(btf_type_match!(match ty {
        BtfKind::Int => format!("{}::default()", type_declaration(ty, anon_types)?),
        BtfKind::Float => format!("{}::default()", type_declaration(ty, anon_types)?),
        BtfKind::Ptr => "std::ptr::null_mut()".to_string(),
        BtfKind::Array(t) => {
            format!(
                "[{}; {}]",
                type_default(t.contained_type(), anon_types)
                    .map_err(|err| anyhow!("in {ty:?}: {err}"))?,
                t.capacity()
            )
        }
        BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64 =>
            format!("{}::default()", anon_types.type_name_or_anon(&ty)),
        BtfKind::Var(t) => format!(
            "{}::default()",
            type_declaration(t.referenced_type(), anon_types)?
        ),
        _ => bail!("Invalid type: {ty:?}"),
    }))
}

pub(crate) fn size_of_type(ty: BtfType<'_>, btf: &Btf<'_>) -> Result<usize> {
    let ty = ty.skip_mods_and_typedefs();

    Ok(btf_type_match!(match ty {
        BtfKind::Int(t) => ((t.bits + 7) / 8).into(),
        BtfKind::Ptr => btf.ptr_size()?.get(),
        BtfKind::Array(t) => t.capacity() * size_of_type(t.contained_type(), btf)?,
        BtfKind::Struct(t) => t.size(),
        BtfKind::Union(t) => t.size(),
        BtfKind::Enum(t) => t.size(),
        BtfKind::Enum64(t) => t.size(),
        BtfKind::Var(t) => size_of_type(t.referenced_type(), btf)?,
        BtfKind::DataSec(t) => t.size(),
        BtfKind::Float(t) => t.size(),
        _ => bail!("Cannot get size of type_id: {ty:?}"),
    }))
}

pub(crate) fn escape_reserved_keyword(identifier: Cow<'_, str>) -> Cow<'_, str> {
    // A list of keywords that need to be escaped in Rust when used for variable
    // names or similar (from https://doc.rust-lang.org/reference/keywords.html#keywords,
    // minus keywords that are already reserved in C).
    let reserved = [
        "Self", "abstract", "as", "async", "await", "become", "box", "crate", "dyn", "enum",
        "final", "fn", "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut",
        "override", "priv", "pub", "ref", "self", "super", "trait", "try", "type", "typeof",
        "unsafe", "unsized", "use", "virtual", "where", "yield",
    ];
    debug_assert_eq!(
        reserved.as_slice(),
        {
            let mut vec = reserved.to_vec();
            vec.sort();
            vec
        },
        "please keep reserved keywords sorted",
    );

    if reserved.binary_search(&identifier.as_ref()).is_ok() {
        Cow::Owned(format!("r#{identifier}"))
    } else {
        identifier
    }
}

#[derive(Debug, Default)]
pub(crate) struct AnonTypes {
    /// A mapping from type to number, allowing us to assign numbers to types
    /// consistently.
    types: RefCell<HashMap<TypeId, usize>>,
}

impl AnonTypes {
    pub fn type_name_or_anon<'s>(&self, ty: &BtfType<'s>) -> Cow<'s, str> {
        match ty.name() {
            None => {
                let mut anon_table = self.types.borrow_mut();
                let len = anon_table.len() + 1; // use 1 index anon ids for backwards compat
                let anon_id = anon_table.entry(ty.type_id()).or_insert(len);
                format!("{ANON_PREFIX}{anon_id}").into()
            }
            Some(n) => n.to_string_lossy(),
        }
    }
}

pub struct GenBtf<'s> {
    btf: Btf<'s>,
    anon_types: AnonTypes,
}

impl<'s> From<Btf<'s>> for GenBtf<'s> {
    fn from(btf: Btf<'s>) -> GenBtf<'s> {
        Self {
            btf,
            anon_types: Default::default(),
        }
    }
}

impl<'s> Deref for GenBtf<'s> {
    type Target = Btf<'s>;
    fn deref(&self) -> &Self::Target {
        &self.btf
    }
}

impl<'s> GenBtf<'s> {
    /// Returns the rust-ified type declaration of `ty` in string format.
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    pub fn type_declaration(&self, ty: BtfType<'s>) -> Result<String> {
        type_declaration(ty, &self.anon_types)
    }

    /// Returns an expression that evaluates to the Default value
    /// of a type(typeid) in string form.
    ///
    /// To be used when creating a impl Default for a structure
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    fn type_default(&self, ty: BtfType<'s>) -> Result<String> {
        type_default(ty, &self.anon_types)
    }

    /// Returns rust type definition of `ty` in string format, including dependent types.
    ///
    /// `ty` must be a struct, union, enum, or datasec type.
    pub fn type_definition(
        &self,
        ty: BtfType<'s>,
        processed: &mut HashSet<TypeId>,
    ) -> Result<String> {
        let is_terminal = |ty: BtfType<'_>| -> bool {
            matches!(
                ty.kind(),
                BtfKind::Void
                    | BtfKind::Int
                    | BtfKind::Float
                    | BtfKind::Ptr
                    | BtfKind::Array
                    | BtfKind::Fwd
                    | BtfKind::Typedef
                    | BtfKind::Volatile
                    | BtfKind::Const
                    | BtfKind::Restrict
                    | BtfKind::Func
                    | BtfKind::FuncProto
                    | BtfKind::Var
                    | BtfKind::DeclTag
                    | BtfKind::TypeTag,
            )
        };

        ensure!(
            !is_terminal(ty),
            "Tried to print type definition for terminal type"
        );

        let mut visitor = DefinitionVisitor {
            btf: &self.btf,
            visited: processed,
            anon_types: &self.anon_types,
            definition: String::new(),
        };
        let () = visit_type_hierarchy(ty, &mut visitor)?;
        Ok(visitor.definition)
    }
}

pub(crate) fn next_type(mut t: BtfType<'_>) -> Result<Option<BtfType<'_>>> {
    loop {
        match t.kind() {
            BtfKind::Struct
            | BtfKind::Union
            | BtfKind::Enum
            | BtfKind::Enum64
            | BtfKind::DataSec => return Ok(Some(t)),
            BtfKind::Array => {
                let a = types::Array::try_from(t).unwrap();
                t = a.contained_type()
            }
            _ => match t.next_type() {
                Some(next) => t = next,
                None => return Ok(None),
            },
        }
    }
}
