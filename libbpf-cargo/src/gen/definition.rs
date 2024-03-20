use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write as _;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

use libbpf_rs::btf::types;
use libbpf_rs::btf::Btf;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::HasSize;

use super::btf::escape_reserved_keyword;
use super::btf::is_struct_packed;
use super::btf::is_unsafe;
use super::btf::next_type;
use super::btf::required_padding;
use super::btf::size_of_type;
use super::btf::type_declaration;
use super::btf::type_default;
use super::btf::AnonTypes;
use super::visit::TypeVisitor;

pub(crate) struct DefinitionVisitor<'input> {
    /// The BTF we use for looking up types.
    ///
    /// This should be the same BTF that we operate on.
    pub btf: &'input Btf<'input>,
    /// A shared helper for naming anonymous types.
    pub anon_types: &'input AnonTypes,
    /// A set of already visited types.
    pub visited: &'input mut HashSet<TypeId>,
    /// The type definition that we generate incrementally.
    pub definition: String,
}

impl<'input> TypeVisitor<'input> for DefinitionVisitor<'input> {
    fn visit_datasec(
        &mut self,
        ty: types::DataSec<'input>,
        dependents: &mut Vec<BtfType<'input>>,
    ) -> Result<()> {
        if !self.visited.insert(ty.type_id()) {
            return Ok(());
        }

        let mut sec_name = match ty.name().map(|s| s.to_string_lossy()) {
            None => bail!("Datasec name is empty"),
            Some(s) if !s.starts_with('.') => bail!("Datasec name is invalid: {s}"),
            Some(s) => s.into_owned(),
        };
        sec_name.remove(0);

        writeln!(self.definition, r#"#[derive(Debug, Copy, Clone)]"#)?;
        writeln!(self.definition, r#"#[repr(C)]"#)?;
        writeln!(self.definition, r#"pub struct {sec_name} {{"#)?;

        let mut offset: u32 = 0;
        for datasec_var in ty.iter() {
            let var = self
                .btf
                .type_by_id::<types::Var<'_>>(datasec_var.ty)
                .context("BTF is invalid! Datasec var does not point to a var")?;

            if var.linkage() == types::Linkage::Static {
                // do not output Static Var
                continue;
            }

            if let Some(next_ty) = next_type(*var)? {
                dependents.push(next_ty);
            }

            let padding =
                required_padding(offset as usize, datasec_var.offset as usize, &var, false)?;
            if padding != 0 {
                writeln!(self.definition, r#"    __pad_{offset}: [u8; {padding}],"#)?;
            }

            // Set `offset` to end of current var
            offset = datasec_var.offset + datasec_var.size as u32;

            writeln!(
                self.definition,
                r#"    pub {var_name}: {var_type},"#,
                var_name = var.name().unwrap().to_string_lossy(),
                var_type = type_declaration(*var, self.anon_types)?
            )?;
        }

        writeln!(self.definition, "}}")?;
        Ok(())
    }

    fn visit_composite(
        &mut self,
        ty: types::Composite<'input>,
        dependents: &mut Vec<BtfType<'input>>,
    ) -> Result<()> {
        if !self.visited.insert(ty.type_id()) {
            return Ok(());
        }

        let packed = is_struct_packed(self.btf, &ty)?;

        // fields in the aggregate
        let mut agg_content: Vec<String> = Vec::new();

        // structs with arrays > 32 length need to impl Default
        // rather than #[derive(Default)]
        let mut impl_default: Vec<String> = Vec::new(); // output for impl Default
        let mut gen_impl_default = false; // whether to output impl Default or use #[derive]

        let mut offset = 0; // In bytes
        for member in ty.iter() {
            let member_offset = match member.attr {
                types::MemberAttr::Normal { offset } => offset,
                // Bitfields are tricky to get correct, if at all possible. For
                // now we just skip them, which results in them being covered by
                // padding bytes.
                types::MemberAttr::BitField { .. } => continue,
            };

            let field_ty = self
                .btf
                .type_by_id::<BtfType<'_>>(member.ty)
                .unwrap()
                .skip_mods_and_typedefs();
            if let Some(next_ty_id) = next_type(field_ty)? {
                dependents.push(next_ty_id);
            }
            let field_name = if let Some(name) = member.name {
                escape_reserved_keyword(name.to_string_lossy())
            } else {
                // Only anonymous unnamed unions should ever have no name set.
                // We just name them the same as their anonymous type. As there
                // can only be one member of this very type, there can't be a
                // conflict.
                self.anon_types.type_name_or_anon(&field_ty)
            };

            // Add padding as necessary
            if ty.is_struct {
                let padding = required_padding(
                    offset,
                    member_offset as usize / 8,
                    &self.btf.type_by_id::<BtfType<'_>>(member.ty).unwrap(),
                    packed,
                )?;

                if padding != 0 {
                    agg_content.push(format!(r#"    pub __pad_{offset}: [u8; {padding}],"#,));

                    impl_default.push(format!(
                        r#"            __pad_{offset}: [u8::default(); {padding}]"#,
                    ));
                }

                if let Some(ft) = self.btf.type_by_id::<types::Array<'_>>(field_ty.type_id()) {
                    if ft.capacity() > 32 {
                        gen_impl_default = true
                    }
                }

                // Rust does not implement `Default` for pointers, no matter if
                // the pointee implements it, and it also doesn't do it for
                // `MaybeUninit` constructs, which we use for "unsafe" types.
                if self
                    .btf
                    .type_by_id::<types::Ptr<'_>>(field_ty.type_id())
                    .is_some()
                    || is_unsafe(field_ty)
                {
                    gen_impl_default = true
                }
            }

            match type_default(field_ty, self.anon_types) {
                Ok(mut def) => {
                    if is_unsafe(field_ty) {
                        def = format!("std::mem::MaybeUninit::new({def})")
                    }

                    impl_default.push(format!(
                        r#"            {field_name}: {field_ty_str}"#,
                        field_ty_str = def
                    ));
                }
                Err(e) => {
                    if gen_impl_default || !ty.is_struct {
                        return Err(e.context("Could not construct a necessary Default Impl"));
                    }
                }
            };

            // Set `offset` to end of current var
            offset = (member_offset / 8) as usize + size_of_type(field_ty, self.btf)?;

            let field_ty_str = type_declaration(field_ty, self.anon_types)?;
            let field_ty_str = if is_unsafe(field_ty) {
                Cow::Owned(format!("std::mem::MaybeUninit<{field_ty_str}>"))
            } else {
                Cow::Borrowed(field_ty_str.as_str())
            };

            agg_content.push(format!(r#"    pub {field_name}: {field_ty_str},"#));
        }

        if ty.is_struct {
            let struct_size = ty.size();
            let padding = required_padding(offset, struct_size, &ty, packed)?;
            if padding != 0 {
                agg_content.push(format!(r#"    pub __pad_{offset}: [u8; {padding}],"#,));
                impl_default.push(format!(
                    r#"            __pad_{offset}: [u8::default(); {padding}]"#,
                ));
            }
        }

        if !gen_impl_default && ty.is_struct {
            writeln!(self.definition, r#"#[derive(Debug, Default, Copy, Clone)]"#)?;
        } else if ty.is_struct {
            writeln!(self.definition, r#"#[derive(Debug, Copy, Clone)]"#)?;
        } else {
            writeln!(self.definition, r#"#[derive(Copy, Clone)]"#)?;
        }

        let aggregate_type = if ty.is_struct { "struct" } else { "union" };
        let packed_repr = if packed { ", packed" } else { "" };

        writeln!(self.definition, r#"#[repr(C{packed_repr})]"#)?;
        writeln!(
            self.definition,
            r#"pub {agg_type} {name} {{"#,
            agg_type = aggregate_type,
            name = self.anon_types.type_name_or_anon(&ty),
        )?;

        for field in agg_content {
            writeln!(self.definition, "{field}")?;
        }
        writeln!(self.definition, "}}")?;

        // if required write a Default implementation for this struct
        if gen_impl_default {
            writeln!(
                self.definition,
                r#"impl Default for {} {{"#,
                self.anon_types.type_name_or_anon(&ty),
            )?;
            writeln!(self.definition, r#"    fn default() -> Self {{"#)?;
            writeln!(
                self.definition,
                r#"        {} {{"#,
                self.anon_types.type_name_or_anon(&ty)
            )?;
            for impl_def in impl_default {
                writeln!(self.definition, r#"{impl_def},"#)?;
            }
            writeln!(self.definition, r#"        }}"#)?;
            writeln!(self.definition, r#"    }}"#)?;
            writeln!(self.definition, r#"}}"#)?;
        } else if !ty.is_struct {
            // write a Debug implementation for a union
            writeln!(
                self.definition,
                r#"impl std::fmt::Debug for {} {{"#,
                self.anon_types.type_name_or_anon(&ty),
            )?;
            writeln!(
                self.definition,
                r#"    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"#
            )?;
            writeln!(self.definition, r#"        write!(f, "(???)")"#)?;
            writeln!(self.definition, r#"    }}"#)?;
            writeln!(self.definition, r#"}}"#)?;

            // write a Default implementation for a union
            writeln!(
                self.definition,
                r#"impl Default for {} {{"#,
                self.anon_types.type_name_or_anon(&ty),
            )?;
            writeln!(self.definition, r#"    fn default() -> Self {{"#)?;
            writeln!(
                self.definition,
                r#"        {} {{"#,
                self.anon_types.type_name_or_anon(&ty)
            )?;
            writeln!(self.definition, r#"{},"#, impl_default[0])?;
            writeln!(self.definition, r#"        }}"#)?;
            writeln!(self.definition, r#"    }}"#)?;
            writeln!(self.definition, r#"}}"#)?;
        }
        Ok(())
    }

    fn visit_enum(&mut self, ty: types::Enum<'_>) -> Result<()> {
        if !self.visited.insert(ty.type_id()) {
            return Ok(());
        }

        let repr_size = match ty.size() {
            1 => "8",
            2 => "16",
            4 => "32",
            8 => "64",
            16 => "128",
            _ => bail!("Invalid enum size: {}", ty.size()),
        };

        let mut signed = "u";
        for value in ty.iter() {
            if value.value < 0 {
                signed = "i";
                break;
            }
        }

        writeln!(
            self.definition,
            r#"#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]"#
        )?;
        writeln!(self.definition, r#"#[repr({signed}{repr_size})]"#)?;
        writeln!(
            self.definition,
            r#"pub enum {name} {{"#,
            name = self.anon_types.type_name_or_anon(&ty),
        )?;

        for (i, value) in ty.iter().enumerate() {
            if i == 0 {
                writeln!(self.definition, r#"    #[default]"#)?;
            }
            writeln!(
                self.definition,
                r#"    {name} = {value},"#,
                name = value.name.unwrap().to_string_lossy(),
                value = value.value,
            )?;
        }

        writeln!(self.definition, "}}")?;
        Ok(())
    }
}
