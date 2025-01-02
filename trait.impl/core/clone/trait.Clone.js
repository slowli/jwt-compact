(function() {
    var implementors = Object.fromEntries([["jwt_compact",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"jwt_compact/alg/enum.ModulusBits.html\" title=\"enum jwt_compact::alg::ModulusBits\">ModulusBits</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"jwt_compact/enum.Claim.html\" title=\"enum jwt_compact::Claim\">Claim</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"jwt_compact/jwk/enum.KeyType.html\" title=\"enum jwt_compact::jwk::KeyType\">KeyType</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Ed25519.html\" title=\"struct jwt_compact::alg::Ed25519\">Ed25519</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs256.html\" title=\"struct jwt_compact::alg::Hs256\">Hs256</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs256Key.html\" title=\"struct jwt_compact::alg::Hs256Key\">Hs256Key</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs256Signature.html\" title=\"struct jwt_compact::alg::Hs256Signature\">Hs256Signature</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs384.html\" title=\"struct jwt_compact::alg::Hs384\">Hs384</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs384Key.html\" title=\"struct jwt_compact::alg::Hs384Key\">Hs384Key</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs384Signature.html\" title=\"struct jwt_compact::alg::Hs384Signature\">Hs384Signature</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs512.html\" title=\"struct jwt_compact::alg::Hs512\">Hs512</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs512Key.html\" title=\"struct jwt_compact::alg::Hs512Key\">Hs512Key</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs512Signature.html\" title=\"struct jwt_compact::alg::Hs512Signature\">Hs512Signature</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.Rsa.html\" title=\"struct jwt_compact::alg::Rsa\">Rsa</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.Empty.html\" title=\"struct jwt_compact::Empty\">Empty</a>"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'a&gt;"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.SecretBytes.html\" title=\"struct jwt_compact::alg::SecretBytes\">SecretBytes</a>&lt;'a&gt;"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/jwk/struct.RsaPrimeFactor.html\" title=\"struct jwt_compact::jwk::RsaPrimeFactor\">RsaPrimeFactor</a>&lt;'a&gt;"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/jwk/struct.RsaPrivateParts.html\" title=\"struct jwt_compact::jwk::RsaPrivateParts\">RsaPrivateParts</a>&lt;'a&gt;"],["impl&lt;'a, H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.UntrustedToken.html\" title=\"struct jwt_compact::UntrustedToken\">UntrustedToken</a>&lt;'a, H&gt;"],["impl&lt;A, T, H&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.SignedToken.html\" title=\"struct jwt_compact::SignedToken\">SignedToken</a>&lt;A, T, H&gt;<div class=\"where\">where\n    A: <a class=\"trait\" href=\"jwt_compact/trait.Algorithm.html\" title=\"trait jwt_compact::Algorithm\">Algorithm</a>,\n    A::<a class=\"associatedtype\" href=\"jwt_compact/trait.Algorithm.html#associatedtype.Signature\" title=\"type jwt_compact::Algorithm::Signature\">Signature</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div>"],["impl&lt;A: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.Renamed.html\" title=\"struct jwt_compact::Renamed\">Renamed</a>&lt;A&gt;"],["impl&lt;A: <a class=\"trait\" href=\"jwt_compact/trait.Algorithm.html\" title=\"trait jwt_compact::Algorithm\">Algorithm</a> + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.Validator.html\" title=\"struct jwt_compact::Validator\">Validator</a>&lt;'_, A, T&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.TimeOptions.html\" title=\"struct jwt_compact::TimeOptions\">TimeOptions</a>&lt;F&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongAlg.html\" title=\"struct jwt_compact::alg::StrongAlg\">StrongAlg</a>&lt;T&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongKey.html\" title=\"struct jwt_compact::alg::StrongKey\">StrongKey</a>&lt;T&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.Claims.html\" title=\"struct jwt_compact::Claims\">Claims</a>&lt;T&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.Header.html\" title=\"struct jwt_compact::Header\">Header</a>&lt;T&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"jwt_compact/struct.Token.html\" title=\"struct jwt_compact::Token\">Token</a>&lt;T, H&gt;"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"jwt_compact/enum.Thumbprint.html\" title=\"enum jwt_compact::Thumbprint\">Thumbprint</a>&lt;N&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[10743]}