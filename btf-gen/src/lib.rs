use std::env::consts::ARCH;
use std::ffi::OsStr;
use std::fs::create_dir_all;
use std::fs::rename;
use std::fs::write;
use std::io;
use std::ops::Deref as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use libbpf_rs::btf::Btf;
use libbpf_rs::libbpf_sys;
use libbpf_rs::ErrorExt as _;
use libbpf_rs::Result;

use tempfile::tempdir;

/// Format a command with the given list of arguments as a string.
fn format_command<C, A, S>(command: C, args: A) -> String
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().fold(
        command.as_ref().to_string_lossy().into_owned(),
        |mut cmd, arg| {
            cmd += " ";
            cmd += arg.as_ref().to_string_lossy().deref();
            cmd
        },
    )
}

/// Run a command with the provided arguments.
fn run<C, A, I, S>(command: C, args: A) -> io::Result<()>
where
    C: AsRef<OsStr>,
    A: IntoIterator<IntoIter = I>,
    I: Iterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let args = args.into_iter();
    let instance = Command::new(command.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .env_clear()
        .args(args.clone())
        .output()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "failed to run `{}`: {err}",
                    format_command(command.as_ref(), args.clone())
                ),
            )
        })?;

    if !instance.status.success() {
        let code = if let Some(code) = instance.status.code() {
            format!(" ({code})")
        } else {
            " (terminated by signal)".to_string()
        };

        let stderr = String::from_utf8_lossy(&instance.stderr);
        let stderr = stderr.trim_end();
        let stderr = if !stderr.is_empty() {
            format!(": {stderr}")
        } else {
            String::new()
        };

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "`{}` reported non-zero exit-status{code}{stderr}",
                format_command(command, args)
            ),
        ))
    } else {
        Ok(())
    }
}

fn extract_libbpf_headers(dir: &Path) -> Result<()> {
    let dir = dir.join("bpf");
    let () = create_dir_all(&dir)
        .with_context(|| format!("failed to create directory `{}`", dir.display()))?;

    for (file_name, contents) in libbpf_sys::API_HEADERS.iter() {
        let path = dir.join(file_name);
        let () = write(&path, contents)
            .with_context(|| format!("failed to write `{}`", path.display()))?;
    }
    Ok(())
}

/// Strip DWARF information from the provided BPF object file.
///
/// We rely on the `libbpf` linker here, which removes debug information as a
/// side-effect.
fn strip_dwarf_info(file: &Path) -> Result<()> {
    let mut temp_file = file.as_os_str().to_os_string();
    let () = temp_file.push(".tmp");

    let () = rename(file, &temp_file).context("failed to rename compiled BPF object file")?;

    let mut linker =
        libbpf_rs::Linker::new(file).context("failed to instantiate libbpf object file linker")?;
    let () = linker
        .add_file(temp_file)
        .context("failed to add object file to BPF linker")?;
    let () = linker.link().context("failed to link object file")?;
    Ok(())
}

/// Compile BPF C code into an object file.
///
/// Necessary header files will be created and will stay co-located next to the
/// BPF C file. Use a temporary directory as necessary if you are not interested
/// in keeping these files.
pub fn compile_bpf<A, I, S>(
    bpf_c_file: &Path,
    output: &Path,
    clang: Option<&Path>,
    clang_args: A,
) -> Result<()>
where
    A: IntoIterator<IntoIter = I>,
    I: Iterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let dir = bpf_c_file.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to retrieve parent of `{}`", bpf_c_file.display()),
        )
    })?;
    let vmlinux = dir.join("vmlinux.h");
    let () = write(&vmlinux, vmlinux::VMLINUX)
        .with_context(|| format!("failed to write `{}`", vmlinux.display()))?;

    let () = extract_libbpf_headers(dir)
        .with_context(|| format!("failed to extract libbpf headers to `{}`", dir.display()))?;

    let arch = match ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "powerpc64" => "powerpc",
        "s390x" => "s390",
        x => x,
    };
    let arch_def = format!("-D__TARGET_ARCH_{arch}");

    let args = [
        OsStr::new("-I"),
        OsStr::new(dir),
        OsStr::new(&arch_def),
        OsStr::new("-g"),
        OsStr::new("-O2"),
        OsStr::new("-target"),
        OsStr::new("bpf"),
        OsStr::new("-c"),
        OsStr::new(&bpf_c_file),
        OsStr::new("-o"),
        OsStr::new(&output),
        // Explicitly disable stack protector logic, which doesn't work with
        // BPF. See https://lkml.org/lkml/2020/2/21/1000.
        OsStr::new("-fno-stack-protector"),
    ]
    .into_iter()
    .map(OsStr::to_os_string)
    .chain(
        clang_args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string()),
    );

    let clang = clang.unwrap_or_else(|| Path::new("clang"));
    let () = run(clang, args)?;

    // Compilation with clang may contain DWARF information that references
    // system specific and temporary paths. That can render our generated
    // skeletons unstable, potentially rendering them unsuitable for inclusion
    // in version control systems. So strip this information.
    let () = strip_dwarf_info(output)
        .with_context(|| format!("failed to strip object file {}", output.display()))?;
    Ok(())
}

/// Generate BTF from C code and load it.
pub fn generate_and_load<A, I, S>(
    c_code: &str,
    clang: Option<&Path>,
    clang_args: A,
) -> Result<Btf<'static>>
where
    A: IntoIterator<IntoIter = I>,
    I: Iterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let dir = tempdir().context("failed to create temporary directory")?;

    let prog = dir.path().join("prog.c");
    let () =
        write(&prog, c_code).with_context(|| format!("failed to write `{}`", prog.display()))?;
    let object = dir.path().join("output.o");

    let () = compile_bpf(&prog, &object, clang, clang_args)
        .with_context(|| format!("failed to compile BPF C code `{}`", prog.display()))?;

    let btf = Btf::from_path(&object)
        .with_context(|| format!("failed to load BTF from `{}`", object.display()))?;
    Ok(btf)
}
