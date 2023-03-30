+++
author = "Diego"
title = "Bank-er-smith Writeup | Hack The Box Uni CTF"
date = "2022-12-02"
description = "Writeup for Bank-er-smith"
tags = [
    "Maths",
    "HTB",
    "RSA",
    "Coppersmith's attack"
]
categories = [
    "Cryptography"
]
math= true
+++

# TL;DR

We are provided with the 1024 - 256 = 768 most significant bits of one of the primes used to compute $n$. Therefore, with the Coppersmith's attack we can find the missing 256 bits and having $p$ it is trivial to break the RSA scheme. 

## Code analysis

First of all, it is important to understand the source code 

Source code:

```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse, GCD
from secret import FLAG, KEY

WELCOME = """
************** Welcome to the Gringatts Bank. **************
*                                                          *
*                  Fortius Quo Fidelius                    *
*                                                          *
************************************************************
"""


class RSA():

    def __init__(self, key_length):
        self.e = 0x10001
        phi = 0
        prime_length = key_length // 2

        while GCD(self.e, phi) != 1:
            self.p, self.q = getPrime(prime_length), getPrime(prime_length)
            phi = (self.p - 1) * (self.q - 1)
            self.n = self.p * self.q

        self.d = inverse(self.e, phi)

    def encrypt(self, message):
        message = bytes_to_long(message)
        return pow(message, self.e, self.n)

    def decrypt(self, encrypted_message):
        message = pow(encrypted_message, self.d, self.n)
        return long_to_bytes(message)


class Bank:

    def __init__(self, rsa):
        self.options = "[1] Get public certificate.\n[2] Calculate Hint.\n[3] Unlock Vault.\n"
        self.shift = 256
        self.vaults = {
            f"vault_{i}": [b"passphrase", b"empty"]
            for i in range(100)
        }
        self.rsa = rsa

    def initializeVault(self, name, passphrase, data):
        self.vaults[name][0] = passphrase
        self.vaults[name][1] = data

    def calculateHint(self):
        return (self.rsa.p >> self.shift) << self.shift

    def enterVault(self, vault, passphrase):
        vault = self.vaults[vault]
        if passphrase.encode() == vault[0]:
            return vault[1].decode()
        else:
            print("\nFailed to open the vault!\n")
            exit(1)


if __name__ == "__main__":
    rsa = RSA(2048)
    bank = Bank(rsa)

    vault = "vault_68"
    passphrase = KEY
    bank.initializeVault(vault, passphrase, FLAG)

    encrypted_passphrase = rsa.encrypt(bank.vaults[vault][0])
    print(f"You managed to retrieve: {hex(encrypted_passphrase)[2:]}")
    print("\nNow you are ready to enter the bank.")
    print(WELCOME)

    while True:
        try:
            print("Hello, what would you like to do?\n")
            print(bank.options)
            option = int(input("> "))

            if option == 1:
                print(f"\n{bank.rsa.n}\n{bank.rsa.e}\n")
            elif option == 2:
                print(f"\n{bank.calculateHint()}\n")
                print(f"real p : {bank.rsa.p}")
            elif option == 3:
                vault = input("\nWhich vault would you like to open: ")
                passphrase = input("Enter the passphrase: ")
                print(f"\n{bank.enterVault(vault, passphrase)}\n")
            else:
                "Abort mission!"
                exit(1)
        except KeyboardInterrupt:
            print("Exiting")
            exit(1)
        except Exception as e:
            print(f"An error occurred while processing data: {e}")
            exit(1)
```

We can see that SELF.SHIFT = 256 and RSA was initialized to have 2048 bit keys:
```rsa = RSA(2048)```
but the length of the primes is: ```key_length // 2```

Therefore, the primes are 1024 bits each. Also, if we look, there is a ```calculateHint``` function:

```python
def calculateHint(self):
    return (self.rsa.p >> self.shift) << self.shift.
```

This function returns the most significant 768 bits of *p*. If we were able to get *p* we could easily break the RSA scheme.

## Mathematical approach

{{< math.inline >}}
{{ if or .Page.Params.math .Site.Params.math }}
<!-- KaTeX -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.11.1/dist/katex.min.css" integrity="sha384-zB1R0rpPzHqg7Kpt0Aljp8JPLqbXI3bhnPWROx27a9N0Ll6ZP/+DiW/UqRcLbRjq" crossorigin="anonymous">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.11.1/dist/katex.min.js" integrity="sha384-y23I5Q6l+B6vatafAwxRu/0oK/79VlbSz7Q9aiSZUvyWYIYsd+qj+o24G5ZU2zJz" crossorigin="anonymous"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.11.1/dist/contrib/auto-render.min.js" integrity="sha384-kWPLUVMOks5AQFrykwIup5lo0m3iMkkHrD0uJ4H5cjeGihAutqP0yW0J6dpFiVkI" crossorigin="anonymous" onload="renderMathInElement(document.body);"></script>
{{ end }}
{{</ math.inline >}}

What we are going to do is to construct a polynomial:
$$
f(x) = hint + x (mod\hspace{0.2cm}p)
$$
Let us define an $x_{0}$ such that:
$$
x_{0} = p - hint
$$
$$
f(x_{0}) = 0
$$
Our goal is to find the root $x_{0}$ so that we can recover $p$ in its entirety:
$$
p = hint + x_{0}
$$

Coppersmith's attack will help us to find a polynomial $pr$ with small coefficients that has the root $x_{0}$. He does all this through the LLL algorithm.

I leave you some references about the Coppersmith's attack that surely explain it much better than me:

https://en.wikipedia.org/wiki/Coppersmith%27s_attack

https://github.com/mimoo/RSA-and-LLL-attacks

https://web.eecs.umich.edu/~cpeikert/lic13/lec04.pdf

https://latticehacks.cr.yp.to/rsa.html

https://www.di.ens.fr/~fouque/ens-rennes/coppersmith.pdf

## Solver

The final solver is:

```python
n = 26211375773469184001318656141100500763313429420913368001374745099484088122316579885286487097911099553640485465879264776561059641793632440822902474437366178151344614399507216375584746495767257118136660752816908128374718028852908424721616601101869767341034562299604200292062539562260031509249703818987605113732956619399024336428546024215912865109661672719548634299576268423724640604152315140125167475937078671855333168331013934992701158252733536256484092658492790979124858563614501772552940266371220754690019124764001836316364805420248302098449705982955010188607337871438867444775767773706448611787974077408317620890183
e = 65537
nbits = n.nbits()
known_bits = 256
hint = 177280817288627322094134834382081312724589047332204205138596571508970320442645568456603184647631801350766801962518302849576529462620705317421396164285474490176804856313329119058781152823294890779368691476727476669843207530678654823924746113011854165428215140997357968931347835865704536810100214150131131351040
PR.<x> = PolynomialRing(Zmod(n))
f = (hint + x)
x0 = f.small_roots(X=2^known_bits, beta=0.4)[0]
p = hint + x0
print (hint + x0)
```
If we run it we can see that we get the value of $p$.

```sh
$ sage solver.sage
177280817288627322094134834382081312724589047332204205138596571508970320442645568456603184647631801350766801962518302849576529462620705317421396164285474490176804856313329119058781152823294890779368691476727476669843207530678654824005037352629664972062758886735010264329580233324956801766609726126137579798151
```
With this value of p we can easily obtain the decrypted message:

```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse, GCD
import gmpy2
p = 177280817288627322094134834382081312724589047332204205138596571508970320442645568456603184647631801350766801962518302849576529462620705317421396164285474490176804856313329119058781152823294890779368691476727476669843207530678654824005037352629664972062758886735010264329580233324956801766609726126137579798151
n = 26211375773469184001318656141100500763313429420913368001374745099484088122316579885286487097911099553640485465879264776561059641793632440822902474437366178151344614399507216375584746495767257118136660752816908128374718028852908424721616601101869767341034562299604200292062539562260031509249703818987605113732956619399024336428546024215912865109661672719548634299576268423724640604152315140125167475937078671855333168331013934992701158252733536256484092658492790979124858563614501772552940266371220754690019124764001836316364805420248302098449705982955010188607337871438867444775767773706448611787974077408317620890183
q = n // p
e = 65537
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
c = int("147242eb8f9b480d9211897b5f1577e23fd595f23f290a0ec5b006c35cd843307749db797c523ca906904c078c04300a6f3af77f15ce19382d40f86b0709ebf23f2fb405d2bfa0dd649813004d83e6eb08a2ccfa8af7a94c69a8b6eb10a2478c181bfec8dc17a8749bd9e50394dd59b527375fdb4095efd95234876e7548c08e452438a081f9b0d7b5d11e0c24bf94946ab772ce7979691930d034829d0a9bb50835d848f4de4850c6c566ea7ba761ed747b7353934924d301e64e6f123f5be140af009acc13f019b5953bf152090752448995f84e6753737697ba8246a966e1357664e93597147bca6c5f4a9abe299382a67a1a5f6c081bd6071e05694c3a23", 16)
m = pow(c, d, n)
print(long_to_bytes(m))
```
Obtained message:

```sh
$ python3 solver.py 
b"The_horcrux_is_Helga_Hufflepuff's_cup"
```

## Flag:

We introduce ```The_horcrux_is_Helga_Hufflepuff's_cup``` as password in the server to open the vault and get the flag:

```sh
HTB{LLL_4nd_c00p325m17h_15_57111_m491c_70_my_3y35}
```

I hope you liked it and learned.