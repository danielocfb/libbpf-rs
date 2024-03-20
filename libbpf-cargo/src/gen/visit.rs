use anyhow::bail;
use anyhow::Result;

use libbpf_rs::btf::types;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf_type_match;

pub(crate) trait TypeVisitor<'btf> {
    fn visit_datasec(
        &mut self,
        ty: types::DataSec<'btf>,
        dependents: &mut Vec<BtfType<'btf>>,
    ) -> Result<()>;

    fn visit_composite(
        &mut self,
        ty: types::Composite<'btf>,
        dependents: &mut Vec<BtfType<'btf>>,
    ) -> Result<()>;

    fn visit_enum(&mut self, ty: types::Enum<'_>) -> Result<()>;
}

/// Visit a type hierarchy with `ty` as the root, in a breadth-first manner.
pub(crate) fn visit_type_hierarchy<'btf, V>(ty: BtfType<'btf>, visitor: &mut V) -> Result<()>
where
    V: TypeVisitor<'btf>,
{
    // Process dependent types until there are none left.
    let mut dependents = vec![ty];
    while !dependents.is_empty() {
        let ty = dependents.remove(0);

        btf_type_match!(match ty {
            BtfKind::Composite(ty) => visitor.visit_composite(ty, &mut dependents)?,
            BtfKind::Enum(ty) => visitor.visit_enum(ty)?,
            BtfKind::DataSec(ty) => visitor.visit_datasec(ty, &mut dependents)?,
            _ => bail!("encountered unsupported type: {:?}", ty.kind()),
        })
    }
    Ok(())
}
