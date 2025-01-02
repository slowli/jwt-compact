(function() {
    var implementors = Object.fromEntries([["jwt_compact",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"https://docs.rs/secp256k1/~0.27/secp256k1/key/struct.PublicKey.html\" title=\"struct secp256k1::key::PublicKey\">PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"https://docs.rs/secp256k1/~0.27/secp256k1/key/struct.SecretKey.html\" title=\"struct secp256k1::key::SecretKey\">SecretKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs256Key.html\" title=\"struct jwt_compact::alg::Hs256Key\">Hs256Key</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs384Key.html\" title=\"struct jwt_compact::alg::Hs384Key\">Hs384Key</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.Hs512Key.html\" title=\"struct jwt_compact::alg::Hs512Key\">Hs512Key</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.RsaPrivateKey.html\" title=\"struct jwt_compact::alg::RsaPrivateKey\">RsaPrivateKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.RsaPublicKey.html\" title=\"struct jwt_compact::alg::RsaPublicKey\">RsaPublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for PublicKey"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for SecretKey"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for SigningKey"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"enum\" href=\"jwt_compact/jwk/enum.JsonWebKey.html\" title=\"enum jwt_compact::jwk::JsonWebKey\">JsonWebKey</a>&lt;'_&gt;&gt; for VerifyingKey"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; for <a class=\"enum\" href=\"jwt_compact/alg/enum.ModulusBits.html\" title=\"enum jwt_compact::alg::ModulusBits\">ModulusBits</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.Hs256Key.html\" title=\"struct jwt_compact::alg::Hs256Key\">Hs256Key</a>&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongKey.html\" title=\"struct jwt_compact::alg::StrongKey\">StrongKey</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.Hs256Key.html\" title=\"struct jwt_compact::alg::Hs256Key\">Hs256Key</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.Hs384Key.html\" title=\"struct jwt_compact::alg::Hs384Key\">Hs384Key</a>&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongKey.html\" title=\"struct jwt_compact::alg::StrongKey\">StrongKey</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.Hs384Key.html\" title=\"struct jwt_compact::alg::Hs384Key\">Hs384Key</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.Hs512Key.html\" title=\"struct jwt_compact::alg::Hs512Key\">Hs512Key</a>&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongKey.html\" title=\"struct jwt_compact::alg::StrongKey\">StrongKey</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.Hs512Key.html\" title=\"struct jwt_compact::alg::Hs512Key\">Hs512Key</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.RsaPrivateKey.html\" title=\"struct jwt_compact::alg::RsaPrivateKey\">RsaPrivateKey</a>&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongKey.html\" title=\"struct jwt_compact::alg::StrongKey\">StrongKey</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.RsaPrivateKey.html\" title=\"struct jwt_compact::alg::RsaPrivateKey\">RsaPrivateKey</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.RsaPublicKey.html\" title=\"struct jwt_compact::alg::RsaPublicKey\">RsaPublicKey</a>&gt; for <a class=\"struct\" href=\"jwt_compact/alg/struct.StrongKey.html\" title=\"struct jwt_compact::alg::StrongKey\">StrongKey</a>&lt;<a class=\"struct\" href=\"jwt_compact/alg/struct.RsaPublicKey.html\" title=\"struct jwt_compact::alg::RsaPublicKey\">RsaPublicKey</a>&gt;"],["impl&lt;'a, H: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.217/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;'a <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.str.html\">str</a>&gt; for <a class=\"struct\" href=\"jwt_compact/struct.UntrustedToken.html\" title=\"struct jwt_compact::UntrustedToken\">UntrustedToken</a>&lt;'a, H&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[8099]}