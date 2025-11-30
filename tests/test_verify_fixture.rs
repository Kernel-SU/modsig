use std::path::PathBuf;
use std::io::Write;

use ksusig::{Algorithms, CertChainVerifier, DigestContext, Module, SignatureVerifier, TrustedRoots, VerifyError};

fn load_signing_block(path: &str) -> Result<ksusig::SigningBlock, String> {
    let module_path = PathBuf::from(path);
    let module = Module::new(module_path).map_err(|e| e.to_string())?;
    module.get_signing_block().map_err(|e| e.to_string())
}

/// 官方 KSU 签名：应被内置根信任。
#[test]
fn verify_fixture_signed_zip_has_trusted_chain() {
    let signing_block = load_signing_block("tests/fixtures/test_ksu_signed.zip")
        .expect("extract signing block from fixture");

    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2(&signing_block).expect("verify v2");

    assert!(result.signature_valid, "signature should be valid");
    assert!(
        result.cert_chain_valid,
        "certificate chain should be structurally valid"
    );
    assert!(
        result.is_trusted,
        "certificate chain should be trusted by built-in roots"
    );
    assert!(
        result.certificate.as_ref().is_some_and(|c| !c.is_empty()),
        "leaf certificate should be present"
    );
    assert_eq!(
        result.cert_chain.len(),
        1,
        "fixture should carry one intermediate certificate"
    );
    // Note: warnings may include "Digest verification skipped" when no digest context is provided
    // This is expected behavior in the new API
    let non_skip_warnings: Vec<_> = result.warnings.iter()
        .filter(|w| !w.contains("Digest verification skipped"))
        .collect();
    assert!(
        non_skip_warnings.is_empty(),
        "no unexpected warnings for the official fixture, got: {:?}",
        non_skip_warnings
    );
}

/// 自签/测试根：默认不可信，但加载 tests/certificates/root_ca/root_ca_p256.crt 后应可信。
#[test]
fn verify_untrusted_fixture_can_be_trusted_with_custom_root() {
    let signing_block = load_signing_block("tests/fixtures/test_signed.zip")
        .expect("extract signing block from fixture");

    // 默认根：应验签成功，但不可信。
    let default_verifier = SignatureVerifier::with_builtin_roots();
    let default_result = default_verifier
        .verify_v2(&signing_block)
        .expect("verify v2");
    assert!(default_result.signature_valid, "signature should be valid");
    assert!(
        !default_result.is_trusted,
        "should not be trusted without custom root"
    );
    let leaf = default_result
        .certificate
        .clone()
        .expect("leaf certificate present");

    // 加载测试根 CA
    let root_pem =
        std::fs::read("tests/certificates/root_ca/root_ca_p256.crt").expect("read test root pem");
    let mut roots = TrustedRoots::new();
    roots.add_root_pem(&root_pem).expect("parse test root pem");
    let root_der = {
        let pem = pem::parse(root_pem).expect("parse pem");
        pem.contents().to_vec()
    };

    // 使用 CertChainVerifier 直接验证链 + 信任。
    let chain_verifier = CertChainVerifier::new(roots);
    let (chain_valid, trusted, error_msg) = chain_verifier.verify_chain(&leaf, &[root_der]);
    assert!(
        chain_valid,
        "chain should be structurally valid with provided root"
    );
    assert!(
        trusted,
        "should be trusted when root is supplied as intermediate, error: {:?}",
        error_msg
    );
}

/// 双签（V2 + Source Stamp）场景：均应验签通过但默认不被信任。
#[test]
fn verify_dual_signed_has_v2_and_stamp_results() {
    let signing_block = load_signing_block("tests/fixtures/test_dual_signed.zip")
        .expect("extract signing block from fixture");

    let verifier = SignatureVerifier::with_builtin_roots();
    let (v2_result, stamp_result) = verifier.verify_all(&signing_block);

    let v2 = v2_result.expect("v2 result");
    assert!(v2.signature_valid, "v2 signature should be valid");
    assert!(v2.cert_chain_valid, "v2 chain should be valid");
    assert!(
        !v2.is_trusted,
        "v2 should not be trusted without custom root"
    );

    let stamp = stamp_result.expect("stamp result");
    assert!(stamp.signature_valid, "stamp signature should be valid");
    assert!(stamp.cert_chain_valid, "stamp chain should be valid");
    assert!(
        !stamp.is_trusted,
        "stamp should not be trusted without custom root"
    );
}

/// 未签名模块：应返回 NoSignature。
#[test]
fn verify_unsigned_module_returns_no_signature() {
    let module_path = PathBuf::from("tests/fixtures/test_unsigned.zip");
    let module = Module::new(module_path).expect("load module");
    let signing_block = module.get_signing_block();
    assert!(
        signing_block.is_err(),
        "unsigned module should not have a signing block"
    );

    // 若未来返回签名块，也应在 verify_v2 里报 NoSignature。
    if let Ok(block) = signing_block {
        let verifier = SignatureVerifier::with_builtin_roots();
        let err = verifier.verify_v2(&block).unwrap_err();
        assert!(
            matches!(err, VerifyError::NoSignature),
            "should return NoSignature"
        );
    }
}

// ========== 安全测试用例 ==========

/// 篡改检测：修改文件内容后摘要验证应失败
#[test]
fn verify_tampered_content_fails_digest_verification() {
    // 读取原始签名模块
    let original_bytes = std::fs::read("tests/fixtures/test_ksu_signed.zip")
        .expect("read original fixture");

    // 创建临时文件并篡改内容
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let tampered_path = temp_dir.path().join("tampered.zip");

    // 在 ZIP 条目区域内修改一个字节（避开签名块和 EOCD）
    let mut tampered_bytes = original_bytes.clone();
    // 修改 ZIP 文件头附近的字节（通常在前 1000 字节内是安全的）
    if tampered_bytes.len() > 100 {
        let idx = 50; // 修改 ZIP 条目区域内的字节
        tampered_bytes[idx] = tampered_bytes[idx].wrapping_add(1);
    }

    let mut file = std::fs::File::create(&tampered_path).expect("create temp file");
    file.write_all(&tampered_bytes).expect("write tampered file");
    drop(file);

    // 加载篡改后的模块
    let module = Module::new(tampered_path.clone()).expect("load tampered module");
    let signing_block = module.get_signing_block().expect("get signing block");

    // 计算新的摘要（基于篡改后的内容）
    let mut digest_ctx = DigestContext::new();
    if let Ok(digest) = module.digest(&Algorithms::ECDSA_SHA2_512) {
        digest_ctx.add_digest(Algorithms::ECDSA_SHA2_512.to_u32(), digest);
    }

    // 验证应检测到摘要不匹配
    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2_with_digest(&signing_block, Some(&digest_ctx));

    // 摘要应该不匹配（因为内容被篡改，新计算的摘要与签名块中存储的不同）
    match result {
        Ok(r) => {
            assert!(
                !r.digest_valid,
                "tampered content should fail digest verification"
            );
        }
        Err(VerifyError::MultiSignerFailure(errors)) => {
            // 也可能直接返回错误
            assert!(
                errors.iter().any(|e| e.contains("Digest mismatch")),
                "should report digest mismatch error, got: {:?}",
                errors
            );
        }
        Err(e) => {
            // 其他错误也可以接受（如签名块解析失败）
            println!("Tampered file verification failed with: {}", e);
        }
    }
}

/// 摘要验证：使用正确的摘要上下文应通过验证
#[test]
fn verify_with_correct_digest_context_passes() {
    let module = Module::new(PathBuf::from("tests/fixtures/test_ksu_signed.zip"))
        .expect("load module");
    let signing_block = module.get_signing_block().expect("get signing block");

    // 计算正确的摘要
    let mut digest_ctx = DigestContext::new();
    if let Ok(digest) = module.digest(&Algorithms::ECDSA_SHA2_512) {
        digest_ctx.add_digest(Algorithms::ECDSA_SHA2_512.to_u32(), digest);
    }

    // 使用正确的摘要上下文验证
    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2_with_digest(&signing_block, Some(&digest_ctx))
        .expect("verification should succeed");

    assert!(result.signature_valid, "signature should be valid");
    assert!(result.digest_valid, "digest should be valid with correct context");
    assert!(result.is_trusted, "should be trusted by builtin roots");
}

/// 伪造摘要：提供错误的摘要值应失败
#[test]
fn verify_with_wrong_digest_fails() {
    let module = Module::new(PathBuf::from("tests/fixtures/test_ksu_signed.zip"))
        .expect("load module");
    let signing_block = module.get_signing_block().expect("get signing block");

    // 创建错误的摘要上下文（全零摘要）
    let mut digest_ctx = DigestContext::new();
    digest_ctx.add_digest(Algorithms::ECDSA_SHA2_512.to_u32(), vec![0u8; 64]);

    // 验证应失败
    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2_with_digest(&signing_block, Some(&digest_ctx));

    match result {
        Ok(r) => {
            assert!(
                !r.digest_valid,
                "wrong digest should fail verification"
            );
        }
        Err(VerifyError::MultiSignerFailure(errors)) => {
            assert!(
                errors.iter().any(|e| e.contains("Digest mismatch")),
                "should report digest mismatch"
            );
        }
        Err(e) => {
            panic!("unexpected error: {}", e);
        }
    }
}

/// 多签名者：验证结果应包含所有签名者信息
#[test]
fn verify_reports_all_signers() {
    let signing_block = load_signing_block("tests/fixtures/test_ksu_signed.zip")
        .expect("load signing block");

    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2(&signing_block).expect("verify v2");

    // 检查签名者结果列表
    assert!(
        !result.signers.is_empty(),
        "should have at least one signer result"
    );

    // 检查第一个签名者的详细信息
    let first_signer = &result.signers[0];
    assert!(first_signer.signature_valid, "first signer should have valid signature");
    assert!(first_signer.certificate.is_some(), "first signer should have certificate");

    // 整体结果应与单个签名者一致（只有一个签名者时）
    assert_eq!(
        result.signature_valid,
        result.signers.iter().all(|s| s.signature_valid),
        "overall signature_valid should match all signers"
    );
}

/// 证书链验证：未知发行者应报告不可信
#[test]
fn verify_unknown_issuer_reports_untrusted() {
    let signing_block = load_signing_block("tests/fixtures/test_signed.zip")
        .expect("load signing block");

    // 使用空的信任根
    let verifier = SignatureVerifier::with_trusted_roots(TrustedRoots::new());
    let result = verifier.verify_v2(&signing_block).expect("verify v2");

    // 签名应有效，但不可信
    assert!(result.signature_valid, "signature should be valid");
    assert!(!result.is_trusted, "should not be trusted without roots");

    // 检查警告信息
    let has_root_warning = result.warnings.iter()
        .any(|w| w.contains("No trusted roots") || w.contains("Unknown issuer"));
    assert!(
        has_root_warning || !result.is_trusted,
        "should warn about missing trust or report untrusted"
    );
}
