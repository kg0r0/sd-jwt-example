package main

import (
	"log"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	sdjwt "github.com/TBD54566975/ssi-sdk/sd-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type lestratSigner struct {
	signer jwx.Signer
}

func (s lestratSigner) Sign(blindedClaimsData []byte) ([]byte, error) {
	insecureSDJWT, err := jwt.ParseInsecure(blindedClaimsData)
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(insecureSDJWT, jwt.WithKey(jwa.KeyAlgorithmFrom(s.signer.ALG), s.signer.PrivateKey))
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func main() {
	issuerPrivKey, issuerDID, err := key.GenerateDIDKey(crypto.P256)
	if err != nil {
		panic(err)
	}
	expandedIssuerDID, err := issuerDID.Expand()
	if err != nil {
		panic(err)
	}
	issuerKID := expandedIssuerDID.VerificationMethod[0].ID

	credentialClaims := []byte(`{
	  "first_name": "Alice",
	  "address": "123 McAlice St, NY",
	  "date_of_birth": "1967-01-24"
	}`)

	issuerSigner, err := jwx.NewJWXSigner(issuerDID.String(), issuerKID, issuerPrivKey)
	if err != nil {
		panic(err)
	}
	signer := sdjwt.NewSDJWTSigner(&lestratSigner{
		*issuerSigner,
	}, sdjwt.NewSaltGenerator(16))

	issuanceFormat, err := signer.BlindAndSign(credentialClaims, map[string]sdjwt.BlindOption{
		"first_name":    sdjwt.RecursiveBlindOption{},
		"address":       sdjwt.RecursiveBlindOption{},
		"date_of_birth": sdjwt.RecursiveBlindOption{},
	})
	if err != nil {
		panic(err)
	}
	log.Println(string(issuanceFormat))

	idxOfDisclosuresToPresent, err := sdjwt.SelectDisclosures(issuanceFormat, map[string]struct{}{"date_of_birth": {}})
	if err != nil {
		panic(err)
	}
	sdPresentation := sdjwt.CreatePresentation(issuanceFormat, idxOfDisclosuresToPresent, nil)
	log.Println(string(sdPresentation))

	issuerKey, err := expandedIssuerDID.VerificationMethod[0].PublicKeyJWK.ToPublicKey()
	if err != nil {
		panic(err)
	}
	processedPayload, err := sdjwt.VerifySDPresentation(sdPresentation,
		sdjwt.VerificationOptions{
			HolderBindingOption: sdjwt.SkipVerifyHolderBinding,
			Alg:                 expandedIssuerDID.VerificationMethod[0].PublicKeyJWK.ALG,
			IssuerKey:           issuerKey,
		})
	if err != nil {
		panic(err)
	}
	log.Println(processedPayload)
}
