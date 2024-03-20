use std::collections::HashSet;
use std::fmt::Write as _;

use anyhow::bail;
use anyhow::Result;

use libbpf_rs::btf::types;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::HasSize;

use super::visit::TypeVisitor;
use super::btf::AnonTypes;

struct DefinitionVisitor<'input> {
    /// A set of already visited types.
    visited: &'input mut HashSet<TypeId>,
    /// A shared helper for naming anonymous types.
    anon_types: &'input AnonTypes,
    /// The type definition that we generate incrementally.
    definition: String,
}

impl TypeVisitor for DefinitionVisitor<'_> {
    fn visit_datasec(
        &mut self,
        ty: types::DataSec<'_>,
        dependents: &mut Vec<BtfType<'_>>,
    ) -> Result<()> {
        Ok(())
    }

    fn visit_composite(
        &mut self,
        ty: types::Composite<'_>,
        dependents: &mut Vec<BtfType<'_>>,
    ) -> Result<()> {
        Ok(())
    }

    fn visit_enum(&mut self, t: types::Enum<'_>) -> Result<()> {
        let repr_size = match t.size() {
            1 => "8",
            2 => "16",
            4 => "32",
            8 => "64",
            16 => "128",
            _ => bail!("Invalid enum size: {}", t.size()),
        };

        let mut signed = "u";
        for value in t.iter() {
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
            name = self.anon_types.type_name_or_anon(&t),
        )?;

        for (i, value) in t.iter().enumerate() {
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
