// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::env;

use cmake::Config;

#[allow(clippy::too_many_lines)]
fn main() {
    println!("cargo:rerun-if-env-changed=NSYNC_REPRO_SEED");
    println!("cargo:rerun-if-env-changed=NSYNC_SKIP_NATIVE");
    println!("cargo:rerun-if-env-changed=PORTABLE");
    println!("cargo:rerun-if-env-changed=NATIVE_CORE_DIR");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");

    let seed = env::var("NSYNC_REPRO_SEED").ok().filter(|s| {
        let s = s.trim();
        s.len() == 10 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
    }).unwrap_or_else(|| {
        "0x1EAFBEEF".to_string()
    });
    println!("cargo:rustc-env=OBS_BUILD_SEED={}", seed);

    let skip_native = env::var("CARGO_FEATURE_CRYPTO_ONLY").is_ok()
        || env::var("NSYNC_SKIP_NATIVE").unwrap_or_default() == "1";
    if skip_native {
        println!("cargo:rerun-if-env-changed=NSYNC_SKIP_NATIVE");
        println!("cargo:warning=Skipping native backend build for crypto-only validation");
        return;
    }

    // PORTABLE=1 → build for any x86_64 Linux (no CPU-specific instructions)
    // Default   → build optimized for THIS exact CPU (-march=native)
    let portable = env::var("PORTABLE").unwrap_or_default() == "1";

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "linux".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    let mut cfg = Config::new(env::var("NATIVE_CORE_DIR").unwrap_or_else(|_| "native_core".to_string()));
    if target_os == "windows" && target_env == "gnu" && env::var("CMAKE_GENERATOR").is_err() {
        cfg.generator("MinGW Makefiles");
    }
    cfg.define("CMAKE_BUILD_TYPE", "Release");

    if portable {
        cfg.define("DARCH", "x86-64");
        cfg.cflag("-O3");
        cfg.cflag("-march=x86-64");
        cfg.cflag("-mtune=generic");
        cfg.cxxflag("-O3");
        cfg.cxxflag("-march=x86-64");
        cfg.cxxflag("-mtune=generic");
    } else {
        cfg.define("DARCH", "native");
        cfg.cflag("-O3");
        cfg.cflag("-march=native");
        cfg.cflag("-mtune=native");
        cfg.cxxflag("-O3");
        cfg.cxxflag("-march=native");
        cfg.cxxflag("-mtune=native");
    }

    // Hide all internal C++ symbols — only explicitly exported symbols visible
    cfg.cflag("-fvisibility=hidden");
    cfg.cxxflag("-fvisibility=hidden");
    cfg.cxxflag("-fvisibility-inlines-hidden");
    // Disable RTTI — strips typeinfo strings e.g. "randomx::InterpretedVm" from binary
    cfg.cxxflag("-fno-rtti");
    // Enable linker GC of unused sections
    cfg.cflag("-ffunction-sections");
    cfg.cflag("-fdata-sections");

    // Static link libstdc++ for portability
    if portable {
        cfg.cflag("-static-libstdc++");
        cfg.cflag("-static-libgcc");
    }

    let build_path = cfg.build();

    println!("cargo:rustc-link-search=native={}/lib64", build_path.display());
    println!("cargo:rustc-link-search=native={}/lib", build_path.display());
    println!("cargo:rustc-link-lib=static=nscore");
    if target_os == "windows" {
        if target_env == "gnu" {
            // Find GCC library search paths automatically
            let output = std::process::Command::new("gcc")
                .arg("-print-search-dirs")
                .output();
            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if line.starts_with("libraries: =") {
                        let path_part = line.trim_start_matches("libraries: =");
                        for path in env::split_paths(path_part) {
                            if path.exists() {
                                println!("cargo:rustc-link-search=native={}", path.display());
                            }
                        }
                    }
                }
            }
            println!("cargo:rustc-link-lib=static=stdc++");
            println!("cargo:rustc-link-lib=static=gcc");
        } else {
            println!("cargo:rustc-link-lib=dylib=msvcrt");
        }
        println!("cargo:rustc-link-lib=advapi32");
    } else {
        let dylib_name = match target_os.as_str() {
            "freebsd" | "macos" | "ios" => "c++",
            _ => "stdc++",
        };
        println!("cargo:rustc-link-lib=dylib={}", dylib_name);
    }
}
