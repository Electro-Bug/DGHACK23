# DGHACK 2023 - Randigma - 150 pts -  1 Solve

## Description

```
Votre oncle, célèbre historien ayant travaillé sur la Seconde Guerre mondiale vous a légué son manoir suite à un terrible accident.

Vous découvrez la demeure cachée par un somptueux bois au travers du quelle rayonne les dernières lueurs du soleil.

Dans l'aile ouest, la collection de casques et de fusils attire votre attention. Sous un drap, vous tirez une grande malle en bois. Celle-ci contient une curieuse machine couverte de poussière et quelques feuilles griffonnées.

Émerveillé, vous réalisez que cette machine est un modèle inconnu du grand public.

Dans un carnet, vous trouvez quelques feuilles jaunes et un message chiffré, sauriez-vous le déchiffrer ?
```

## Ciphertext

```
PNJIXNFMLGISNBDCLWAVTWYJWORAEUKENBGWYUZDZUAIDSIMHOEQIXYZEJKNAERVBVLLQRXLJWWJKAUERCTLJFOHHAFVLXOXBKAQOJLPRMHCAXFOCFZVPUJTTTTGXTWGXVKTKTNVEFAZCUTJNPTUGMSDGCHYSZFCBEWYYRAFGSIADWECHVDRDJJBDLSNIONHVLXXZVPURFYIWXMZZBFSUXOMUZTLPZLQDHEIRYWBCDNYQSLPXAFYZZZXTQQZHTDOVOHOXOYZNKALETLCZWNMUJXDAKZZQAKLSZGOAQRIMLTHTXOSJUADQSGNJTTLWOQATFXZHZLNRNXIAESGLQOTSFWNXUVLORQOJLXWLHQHBZIMLFGLGDFNVPHZZPACVNBYIJCBFSLPNQHIJUAZJNYQDFRNPPQODUIVFWSADUGTTFRPCITGVMNBOSICECBQHIZQGJMFFBUMKBBAVAYZFLGIWLHCYSAFQOVJHGKEYFXDGCTEZDCOUMEGLFZCZURALHU
```

## Photo

```
Ringstellung  		: ? 11 15
Grundstellung 		: ? 19 ?
Steckerbindungen 	: CK
Zufallswert 		: 15??--??
Walzenlage		: ?
```

## machine.zip

C source code...

# 0 - Read the C source code

The code analysis indicates two things:

- We will need to implement the deciphering algortihm ourself,
- Don't believe the C code,

## main.c

Nothing to see here ...

```c
#include "enigma.h"
#include <stdio.h>


int main(){
	EnigmaMachine createMachine();
	return 0;
}

```

## customrandom.c

Here the code is not at all optimized and slow down deliberately with the loop in **createCustomrandom**. The initial current state value **1774230971** is above the modulo value **134217727**. A **null seed** will generate a predictable random number of **0** at each iteration. There is a need to fix this !

```c
#include "customrandom.h"

Customrandom createCustomrandom(long seed){
	Customrandom custr = malloc(sizeof(Customrandom));
	custr->state = 1774230971;


	for(long i=0;i<seed;i++){
		generateRandom(custr);
	}

	return custr;
}

long generateRandom(Customrandom custr){

	long state = custr->state;
	long newState = (2921555 * state) % 134217727;

	custr->state = newState;

	return newState;

}
```

## I wanna get freed

enigma.c, rotor.c, reflector.c and plugboard.c does not have the same number of malloc and free call... Need to fix this !

```bash
grep -o -i malloc rotor.c| wc -l
4
grep -o -i malloc reflector.c| wc -l
2
grep -o -i malloc plugboard.c| wc -l
2
grep -o -i malloc enigma.c| wc -l
1
grep -o -i free rotor.c| wc -l
3
grep -o -i free reflector.c| wc -l
0
grep -o -i free plugboard.c| wc -l
0
grep -o -i free enigma.c| wc -l
3
```

## The novelty of having two reflectors

In enigma.c, two reflectors are to be provided. The reflector used for ciphering/deciphering is selected based on the output of the linear congruential generator defined in customrandom.c

```c
// put the letter througth the reflector according to the rng
	if(generateRandom(mach->custr)%2==0){
		res = cipherWithReflector(mach->reflector1,res);
	}
	else{
		res = cipherWithReflector(mach->reflector2,res);
	}
```

# 1 - C Code correction and implementation

The first objective is to set up the enigma machine to be able to cipher and decipher text of our choice.  The focus was not to have a clear & clean C-code but something with the solely purpose of solving this challenge. For the implementation verification checks:

- Use any other Enigma implementation to validate the ciphering and deciphering functions,
- You will need to **use the same reflector twice**,
- Some impementation of the Enigma machine have the rotors and all setting in the reverse
  - The first rotor to move is the right one,
  - In other implementation it could be the left one. 

# 2 - Breaking Orginal Enigma

From this point forward, we have a functional enigma machine to play with. The way to break the enigma machine ciphering is to calculate the **coincidence indice (IC)**. If note obvious, please have look to this tutorial **Cracking Enigma in 2021 - Computerphile**. Please remember, we are not dealing with the orginal enigma machine but with a modified one.

Same approach as above, save your time and find a C implementation of the **coincidence index** and insert it into the provided C code of the challenge.

# 3 - Breakthrough

For the validation of the modified enigma machine, we have used twice the same reflector (for **mach->reflector1** and **mach->reflector2**). This has the following consequences or impacts:

- The **seed a no effect anymore** the the same reflector is used,
- **if the LCG is balanced** between odd and even numbers, then the IC will increase when one of the two reflectors used will be selected,
- **if the LCG is unbalanced** , then the most used reflector will provide the highest IC.

# 4 - Bruteforcing - Part 1

In the implementation provided within this solve, we bruteforce the following function over:

- **i, j, k** from 1 to 5 (rotors)
- **l** from 1 to 3, note **l** is used twice (ie a single reflector)
- **n, o, p** from 0 to 25 (missing Grundstellung and Ringstellung)

```c
IC = solve(i,j,k,l,l,n,19,o,p,11,15,0,alphabet,0);
```

so we found

```
4 1 3 3 3 0 4 22 | 0.042117
```

That is to say:

```
Ringstellung  		: 22 11 15
Grundstellung 		: 0 19 4
Steckerbindungen 	: CK
Zufallswert 		: 15??--??
Walzenlage		: 4 1 3
Reflectors		: 3?
```

So we found one reflector over the two !

# Plugboard Analysis

For the plugboard with trials and errors we determine quickly the following one, by maximizing the IC.

```c
plugLetter(plug,'O','N');
plugLetter(plug,'V','R');
plugLetter(plug,'O','N');
plugLetter(plug,'K','C');
plugLetter(plug,'V','R');
plugLetter(plug,'J','A');
plugLetter(plug,'Z','M');
```

# Bruteforce part 2

Then, with the save solving function core, we bruteforce:

- The seed to infinite and beyond,
- The first reflector from 1 to 3,
- The second reflector from 1 to 3.

For use to find:

- **Seed of 8132820**
- **First reflector is 2**
- **Second reflector is 3**

```
IC = _solve(i,j,k,2,3,n,19,o,p,11,15,8132820,alphabet,0);
```



# Plaintext & Flag

```
BRAVO POUR AVOIR TROUVER MON MESSAGE SECRET JE SUIS SURPRIS QUE CELUI CI SOIT DECOUVERT ALORS QUE LA MACHINE A ETE MODIFIEE POUR EVITER LES PROBLEMES EN CHOISSISANT ALEATOIREMENT LE REFLECTEUR NOUS DEVONS ENVOYER NOS TROUPES A LA FRONTIERE CAR L ENNEMI APPROCHE A GRANS PAS METTEZ EN PLACE UNE CELLULE DE CRISE ET PREPARER VOUS NOS ESPOIRS REPOSENT SUR VOUS CAPITAINE LE DRAPEAUD EVALIDATION EST ENIGMAESTUNEMACHINEINCROYABLE MAINTENANT IL FAUT QUE NOUS GAGNONS CETTE BATAILLE ET QUE LA FRANCE REDEVIENNENT LIBRE NOUS COMPTONS SUR VOUS COMMANDANT LAVENIR DE NOTRE PAYS DEPENT DE VOUS MAINTENANT BON COURAGE
```

**DGHACK{ENIGMAESTUNEMACHINEINCROYABLE}**

# Thanks to the author(s)!



Electro / TheMagician

