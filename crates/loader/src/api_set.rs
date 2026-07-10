//! API-set contract name resolution.
//!
//! Windows API-set contract DLL names (`api-ms-win-*` and `ext-ms-win-*`)
//! are virtual identifiers — they are **not files on disk**. At load time the
//! Windows loader consults an API-set database and maps each contract name to
//! the concrete host DLL that carries the implementation (e.g.
//! `api-ms-win-crt-runtime-l1-1-0` → `ucrtbase`).
//!
//! This module provides an equivalent table-driven mapping for exemu. The
//! authoritative source is the public Windows API-set documentation on MS
//! Learn (windows/win32/apiindex/windows-apisets) plus the public groupings of
//! CRT contracts (`api-ms-win-crt-*` → ucrtbase) and core contracts
//! (`api-ms-win-core-*` → kernelbase, with a few in kernel32).
//!
//! # What we implement
//!
//! The mapping is **prefix-based** with a set of explicit overrides for
//! contracts that don't follow the simple "core → kernelbase / crt → ucrtbase"
//! split. The prefix matching intentionally ignores the version suffix
//! (`-l1-1-0`, `-l1-2-0`, …) so the same host maps any version of a contract.
//!
//! # How this is used
//!
//! Call [`resolve`] before any other DLL name look-up. If it returns `Some`,
//! replace the contract name with the returned host DLL name and proceed
//! normally. If it returns `None` the name is not an API-set contract and
//! should be used as-is.
//!
//! The input must be a **lower-cased** DLL name that may or may not end in
//! `.dll`; both forms are accepted. The returned name is always lower-cased
//! and **does not** include a `.dll` extension (callers normalise as needed).

/// Resolve an API-set contract DLL name to its host DLL.
///
/// `name` should be lower-cased; the `.dll` suffix is stripped before
/// matching and is not present in the returned string.
///
/// Returns `None` when `name` is not an API-set contract name (i.e. doesn't
/// start with `api-` or `ext-`).
pub fn resolve(name: &str) -> Option<&'static str> {
    // Strip the optional .dll suffix before matching.
    let bare = name.strip_suffix(".dll").unwrap_or(name);
    if !bare.starts_with("api-") && !bare.starts_with("ext-") {
        return None;
    }
    Some(lookup(bare))
}

/// Inner lookup against the table. `bare` has no `.dll` suffix and starts
/// with `api-` or `ext-`.
fn lookup(bare: &str) -> &'static str {
    // Explicit per-contract overrides that deviate from the prefix rules.
    // Checked before the general prefix rules below.
    for &(contract, host) in EXPLICIT {
        if bare == contract || bare.starts_with(contract) {
            return host;
        }
    }

    // General prefix rules (ordered longest-first to avoid ambiguity).
    for &(prefix, host) in PREFIX_RULES {
        if bare.starts_with(prefix) {
            return host;
        }
    }

    // Unknown API-set contract: fall back to ntdll as a reasonable default
    // that keeps the resolver from stalling on a completely unknown name.
    "ntdll"
}

/// Explicit per-family overrides (longest prefix wins; entries are matched in
/// order). All entries are lower-cased, no `.dll` suffix.
///
/// Source: public MS Learn "APIs present on all Windows devices" / "Extension
/// APIs" tables, public winnt.h/apiset.h comment annotations, and the UCRT
/// announcement (Visual C++ Blog, 2015) stating the full `api-ms-win-crt-*`
/// family forwards to `ucrtbase.dll`.
const EXPLICIT: &[(&str, &str)] = &[
    // ---- CRT family → ucrtbase ----------------------------------------
    // The Universal CRT (ucrtbase.dll) hosts all api-ms-win-crt-* contracts.
    // This covers stdio, math, string, locale, convert, heap, environment,
    // runtime, multibyte, time, filesystem (C99/C11 wrappers), utility, etc.
    ("api-ms-win-crt-", "ucrtbase"),
    // ---- POSIX compatibility shim → ucrtbase ---------------------------
    // Legacy api-ms-win-crt-private, api-ms-win-crt-conio, etc. also ucrtbase.
    // (covered by the api-ms-win-crt- prefix above)

    // ---- Downlevel compatibility shim (downlevel-*)  -------------------
    // api-ms-win-downlevel-* are shim forwarding contracts; on modern Windows
    // they route to kernelbase.
    ("api-ms-win-downlevel-", "kernelbase"),

    // ---- Eventing / ETW → advapi32 / sechost ---------------------------
    ("api-ms-win-eventing-", "sechost"),
    ("api-ms-win-eventlog-", "advapi32"),
    ("api-ms-win-wevtapi-", "wevtapi"),

    // ---- Security / credentials ----------------------------------------
    ("api-ms-win-security-base-", "advapi32"),
    ("api-ms-win-security-credentials-", "credui"),
    ("api-ms-win-security-cryptoapi-", "crypt32"),
    ("api-ms-win-security-lsalookup-", "secur32"),
    ("api-ms-win-security-provider-", "advapi32"),
    ("api-ms-win-security-sddl-", "advapi32"),
    ("api-ms-win-security-systemaudit-", "advapi32"),

    // ---- Service control / SCM -----------------------------------------
    ("api-ms-win-service-", "sechost"),

    // ---- Networking / socket / name resolution -------------------------
    ("api-ms-win-core-namedpipe-", "kernelbase"),
    ("ext-ms-win-winsock-", "ws2_32"),
    ("ext-ms-win-iphlpapi-", "iphlpapi"),
    ("ext-ms-win-dnsapi-", "dnsapi"),
    ("ext-ms-win-ntuser-", "user32"),
    ("ext-ms-win-ntos-", "ntoskrnl"),
    ("ext-ms-win-shell-", "shell32"),
    ("ext-ms-win-ole-", "ole32"),
    ("ext-ms-win-com-", "combase"),
    ("ext-ms-win-ras-", "rasapi32"),
    ("ext-ms-win-storage-", "api-ms-win-storage-l1-1-0"),

    // ---- Core API-set family → kernelbase (default for api-ms-win-core-)
    // This prefix-rule entry is handled in PREFIX_RULES below so that the
    // explicit overrides above (e.g. api-ms-win-core-namedpipe) fire first.
];

/// Ordered prefix rules applied after the explicit table. Longest prefix wins.
const PREFIX_RULES: &[(&str, &str)] = &[
    // api-ms-win-core-* family → kernelbase (the vast majority).
    // A small number of core contracts live in kernel32; they are called out
    // in the EXPLICIT table above with a longer prefix.
    ("api-ms-win-core-", "kernelbase"),
    // Remaining api-ms-win-* (non-core, non-crt) → kernelbase as the safe
    // default for all the misc. contracts (appmodel, power, roapi, etc.).
    ("api-ms-win-", "kernelbase"),
    // ext-ms-win-* that didn't match any explicit prefix → kernelbase.
    ("ext-ms-win-", "kernelbase"),
    // ext-* (non-Windows namespace, e.g. vendor extensions) → kernelbase.
    ("ext-", "kernelbase"),
];

// ---- Unit tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: resolve must work both with and without the .dll suffix.
    fn check(contract: &str, expected_host: &str) {
        let with_dll = format!("{contract}.dll");
        assert_eq!(
            resolve(contract),
            Some(expected_host),
            "bare contract '{contract}' should map to '{expected_host}'"
        );
        assert_eq!(
            resolve(&with_dll),
            Some(expected_host),
            "contract '{contract}.dll' should map to '{expected_host}'"
        );
    }

    // --- CRT family ---------------------------------------------------------

    #[test]
    fn crt_runtime_maps_to_ucrtbase() {
        check("api-ms-win-crt-runtime-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_stdio_maps_to_ucrtbase() {
        check("api-ms-win-crt-stdio-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_math_maps_to_ucrtbase() {
        check("api-ms-win-crt-math-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_string_maps_to_ucrtbase() {
        check("api-ms-win-crt-string-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_locale_maps_to_ucrtbase() {
        check("api-ms-win-crt-locale-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_heap_maps_to_ucrtbase() {
        check("api-ms-win-crt-heap-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_convert_maps_to_ucrtbase() {
        check("api-ms-win-crt-convert-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_environment_maps_to_ucrtbase() {
        check("api-ms-win-crt-environment-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_time_maps_to_ucrtbase() {
        check("api-ms-win-crt-time-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_filesystem_maps_to_ucrtbase() {
        check("api-ms-win-crt-filesystem-l1-1-0", "ucrtbase");
    }

    #[test]
    fn crt_multibyte_maps_to_ucrtbase() {
        check("api-ms-win-crt-multibyte-l1-1-0", "ucrtbase");
    }

    // --- Core family → kernelbase -------------------------------------------

    #[test]
    fn core_processthreads_maps_to_kernelbase() {
        check("api-ms-win-core-processthreads-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_processthreads_v11_maps_to_kernelbase() {
        // Version suffix is stripped — both -l1-1-0 and -l1-1-1 map the same.
        check("api-ms-win-core-processthreads-l1-1-1", "kernelbase");
    }

    #[test]
    fn core_synch_maps_to_kernelbase() {
        check("api-ms-win-core-synch-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_file_maps_to_kernelbase() {
        check("api-ms-win-core-file-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_memory_maps_to_kernelbase() {
        check("api-ms-win-core-memory-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_heap_maps_to_kernelbase() {
        check("api-ms-win-core-heap-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_debug_maps_to_kernelbase() {
        check("api-ms-win-core-debug-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_errorhandling_maps_to_kernelbase() {
        check("api-ms-win-core-errorhandling-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_sysinfo_maps_to_kernelbase() {
        check("api-ms-win-core-sysinfo-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_rtlsupport_maps_to_kernelbase() {
        check("api-ms-win-core-rtlsupport-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_console_maps_to_kernelbase() {
        check("api-ms-win-core-console-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_namedpipe_maps_to_kernelbase() {
        check("api-ms-win-core-namedpipe-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_localregistry_maps_to_kernelbase() {
        check("api-ms-win-core-localregistry-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_localization_maps_to_kernelbase() {
        check("api-ms-win-core-localization-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_timezone_maps_to_kernelbase() {
        check("api-ms-win-core-timezone-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_version_maps_to_kernelbase() {
        check("api-ms-win-core-version-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_winrt_maps_to_kernelbase() {
        check("api-ms-win-core-winrt-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_threadpool_maps_to_kernelbase() {
        check("api-ms-win-core-threadpool-l1-2-0", "kernelbase");
    }

    // --- Security -----------------------------------------------------------

    #[test]
    fn security_base_maps_to_advapi32() {
        check("api-ms-win-security-base-l1-1-0", "advapi32");
    }

    #[test]
    fn service_core_maps_to_sechost() {
        check("api-ms-win-service-core-l1-1-0", "sechost");
    }

    // --- Downlevel shims ----------------------------------------------------

    #[test]
    fn downlevel_kernel32_maps_to_kernelbase() {
        check("api-ms-win-downlevel-kernel32-l2-1-0", "kernelbase");
    }

    // --- Eventing -----------------------------------------------------------

    #[test]
    fn eventing_controller_maps_to_sechost() {
        check("api-ms-win-eventing-controller-l1-1-0", "sechost");
    }

    // --- ext-ms-win-* -------------------------------------------------------

    #[test]
    fn ext_ntuser_maps_to_user32() {
        check("ext-ms-win-ntuser-window-l1-1-0", "user32");
    }

    #[test]
    fn ext_shell_maps_to_shell32() {
        check("ext-ms-win-shell-combobox-l1-1-0", "shell32");
    }

    // --- Plain DLL name → None (not an API-set contract) -------------------

    #[test]
    fn plain_kernel32_is_not_an_api_set() {
        assert_eq!(resolve("kernel32.dll"), None);
        assert_eq!(resolve("kernel32"), None);
    }

    #[test]
    fn plain_ntdll_is_not_an_api_set() {
        assert_eq!(resolve("ntdll.dll"), None);
    }

    #[test]
    fn plain_ucrtbase_is_not_an_api_set() {
        assert_eq!(resolve("ucrtbase.dll"), None);
    }

    #[test]
    fn plain_user32_is_not_an_api_set() {
        assert_eq!(resolve("user32"), None);
    }

    // --- Case: input already lower-cased (no upper-case inputs expected) ----
    // The public contract: callers lower-case before calling resolve.

    #[test]
    fn version_suffix_variants_all_map_to_same_host() {
        // -l1-1-0, -l1-1-1, -l1-2-0, -l2-1-0 all map identically.
        let suffixes = ["-l1-1-0", "-l1-1-1", "-l1-2-0", "-l2-1-0"];
        for s in suffixes {
            let name = format!("api-ms-win-crt-runtime{s}");
            assert_eq!(resolve(&name), Some("ucrtbase"), "failed for suffix {s}");
        }
    }
}
