pub fn resolve(name: &str) -> Option<&'static str> {
    let bare = name.strip_suffix(".dll").unwrap_or(name);
    if !bare.starts_with("api-") && !bare.starts_with("ext-") {
        return None;
    }
    Some(lookup(bare))
}

fn lookup(bare: &str) -> &'static str {
    for &(contract, host) in EXPLICIT {
        if bare == contract || bare.starts_with(contract) {
            return host;
        }
    }

    for &(prefix, host) in PREFIX_RULES {
        if bare.starts_with(prefix) {
            return host;
        }
    }

    "ntdll"
}

const EXPLICIT: &[(&str, &str)] = &[
    ("api-ms-win-crt-", "ucrtbase"),

    ("api-ms-win-downlevel-", "kernelbase"),

    ("api-ms-win-eventing-", "sechost"),
    ("api-ms-win-eventlog-", "advapi32"),
    ("api-ms-win-wevtapi-", "wevtapi"),

    ("api-ms-win-security-base-", "advapi32"),
    ("api-ms-win-security-credentials-", "credui"),
    ("api-ms-win-security-cryptoapi-", "crypt32"),
    ("api-ms-win-security-lsalookup-", "secur32"),
    ("api-ms-win-security-provider-", "advapi32"),
    ("api-ms-win-security-sddl-", "advapi32"),
    ("api-ms-win-security-systemaudit-", "advapi32"),

    ("api-ms-win-service-", "sechost"),

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

];

const PREFIX_RULES: &[(&str, &str)] = &[
    ("api-ms-win-core-", "kernelbase"),
    ("api-ms-win-", "kernelbase"),
    ("ext-ms-win-", "kernelbase"),
    ("ext-", "kernelbase"),
];

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn core_processthreads_maps_to_kernelbase() {
        check("api-ms-win-core-processthreads-l1-1-0", "kernelbase");
    }

    #[test]
    fn core_processthreads_v11_maps_to_kernelbase() {
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

    #[test]
    fn security_base_maps_to_advapi32() {
        check("api-ms-win-security-base-l1-1-0", "advapi32");
    }

    #[test]
    fn service_core_maps_to_sechost() {
        check("api-ms-win-service-core-l1-1-0", "sechost");
    }

    #[test]
    fn downlevel_kernel32_maps_to_kernelbase() {
        check("api-ms-win-downlevel-kernel32-l2-1-0", "kernelbase");
    }

    #[test]
    fn eventing_controller_maps_to_sechost() {
        check("api-ms-win-eventing-controller-l1-1-0", "sechost");
    }

    #[test]
    fn ext_ntuser_maps_to_user32() {
        check("ext-ms-win-ntuser-window-l1-1-0", "user32");
    }

    #[test]
    fn ext_shell_maps_to_shell32() {
        check("ext-ms-win-shell-combobox-l1-1-0", "shell32");
    }

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

    #[test]
    fn version_suffix_variants_all_map_to_same_host() {
        let suffixes = ["-l1-1-0", "-l1-1-1", "-l1-2-0", "-l2-1-0"];
        for s in suffixes {
            let name = format!("api-ms-win-crt-runtime{s}");
            assert_eq!(resolve(&name), Some("ucrtbase"), "failed for suffix {s}");
        }
    }
}
