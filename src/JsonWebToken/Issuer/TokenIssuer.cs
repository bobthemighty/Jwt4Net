using System;
using System.Collections.Generic;
using Jwt4Net.Claims;
using Jwt4Net.Configuration;
using LitJson;
using Jwt4Net.Signing;
using Microsoft.Practices.ServiceLocation;

namespace Jwt4Net.Issuer
{
    public class TokenIssuer : ITokenIssuer
    {
        private readonly ICryptoProvider _cryptoProvider;
        Dictionary<string, IJsonSerializable> claims;
        private readonly IIssuerConfig _config;

        public TokenIssuer(ICryptoProvider cryptoProvider, IIssuerConfig config)
        {
            _cryptoProvider = cryptoProvider;
            _config = config;
            claims = new Dictionary<string, IJsonSerializable>();
            Set(KnownClaims.Issuer, config.IssuerName);
        }

        public void Set<T>(IClaim<T> claim)
        {
            if (claims.ContainsKey(claim.Name))
                claims[claim.Name] = claim;
            else
                claims.Add(claim.Name, claim);
        }

        public void Set<T>(IClaimDescriptor<T> key, T value)
        {
            Set(new Claim<T>(key.Name, value));
        }

        public string Sign()
        {
            var w = new JsonWriter { PrettyPrint = false, IndentValue = 0};
            w.WriteObjectStart();
            foreach (var s in claims.Values)
                s.Serialize(w);
            w.WriteObjectEnd();

            var key = _config.Key;
            var headerSegment = new JsonWebTokenHeader
                                    {
                                        Algorithm = key.Algorithm,
                                        KeyUri = new Uri(key.RemoteUri),
                                        KeyId = key.RemoteId,
                                        KeyFormat = key.KeyFormat
                                    }.ToJson().Base64UrlEncode();
            var claimSegment = w.ToString().Base64UrlEncode();

            var signer = _cryptoProvider.GetSigner();
            var signature = signer.GetSignature(headerSegment+"."+claimSegment);

            return headerSegment + "." + claimSegment + "." + signature.Base64UrlEncode();
        }

        public ITokenIssuer Create()
        {
            return ServiceLocator.Current.GetInstance<ITokenIssuer>();
        }
    }
}
