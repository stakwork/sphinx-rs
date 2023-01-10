```
                                    KEY GENERATION

1.   Generate a scalar polynomial for key generation, where number of scalars  = threshold

2.   Create a vector of points by multiplying each scalar by G

3.
                          Share publicly the vector of points
                        ◄────────────────────────────────────►

4.   Use the vector of points[2] and your secret scalar polynomical[1] to generate secret shares (scalars)

     and a proof of possession (ie signatures)

5.
                         Send each secret share to its intended participant securely
                        ◄────────────────────────────────────►


                         Send your pop signature to all participants
                        ◄────────────────────────────────────►

6.  Combine all received shares into your long-lived secret share of the joint public key

7.  Double check the pop signature you received against the vector of points from step 3


                                SIGNATURE PRODUCTION

8.  Convert the frost key into an x-only BIP340 key

9.  Generate unique session id for this signing session

10. Use your secret share, thenull frost key, and the session id to generate a secret / public nonce

11.
                           Send your public nonce to all the participants
                         ◄────────────────────────────────────►

12. Produce your own partial signature using your secret share, secret nonce, and public nonces of other participants

13.
                          Send your partial signature to all the participants
                         ◄────────────────────────────────────►

14. Verify the partial signatures, and combine them to produce the final single signature.
```
