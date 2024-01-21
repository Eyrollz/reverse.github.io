---
title: Partie 11 - Structures de contrôle - les sauts et conditions (2/3)
date: 2023-10-20 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Structures de contrôle : les sauts et conditions

Nous nous étions arrêtés à ces deux instructions :

```nasm
cmp dword ptr [eax], 2
jz short loc_12B2
```

Pour ce qui est de la comparaison, vous avez compris à quoi elle sert. Intéressons nous maintenant au saut `jz short loc_12B2`. Décortiquons tout d'abord cette instruction :

- `jz` : **type** de saut (ici : *jump if zero*)
- `short` : **distance** du saut
- `loc_12B2` : **adresse de destination**. IDA aime bien préfixer de manière générale les adresses censées contenir du code, ne soyez pas embrouillés par cela. On va faire comme s'il n'y avait marqué que `0x12B2`.

> Les sauts en assembleur peuvent également être appelés **branchements**.
{: .prompt-tip }

> **Astuce IDA** : Les adresses préfixées (labels), noms de variables et noms de fonctions peuvent être renommées avec le raccourcis `N`.
{: .prompt-tip }

## Les distances de sauts

Les **distances de sauts** ne nous intéressent pas tant que ça en *reverse* mais profitons en pour en toucher quelques mots.

Les distances de sauts étaient importantes lorsque les processeurs étaient en 16 bits car il n'était pas possible d'accéder à n'importe quelle zone mémoire avec seulement 16 bits. Ainsi, plusieurs registres étaient utilisés pour pouvoir accéder au segment de code (registre `CS`), à la zone mémoire de la *stack* (registre `SS`) ...

Ainsi une adresse était désigné par un **préfixe** (segment) et un **offset**, par exemple : `CS:0x1234` où `CS` a une valeur de 16 bits.

Ainsi les sauts courts (`short` ou `near`) permettaient de sauter vers une adresse située dans le **même segment**.

Tandis que les sauts longs (`far`) permettaient de sauter plus loin vers une adresse qui pouvait être dans un **autre segment**.

En 32 bits, et à plus forte raison en 64 bits, il est possible de sauter **directement** à n'importer quelle adresse sans avoir à se préoccuper du segment de destination.

## Les types de sauts

Il existe principalement **deux types de sauts** en assembleur x86 :

- Les **sauts inconditionnels** : Il s'agit d'un saut vers une adresse qui sera toujours réalisé, sans aucune condition particulière.
	- **Exemple** : Lorsque l’instruction `jmp 0x401020` sera exécutée, `eip` aura pour valeur `0x401020` dans tous les cas. 
- Les **sauts conditionnels** : Il s'agit d'instructions dont le saut n'est réalisé que sous certaines conditions.
	- **Exemple** : `jz` n'est réalisé que lorsque `ZF == 1`tandis que `jge` n'est réalisé que lorsque `SF == OF`

### Les sauts inconditionnels

Les **sauts inconditionnels** sont les sauts qui sont exécutés dans tous les cas. Nous en avons au moins un dans notre programme, plus précisément dans `main` :

![](/assets/images/introduction_au_reverse/jmp.png)

Cela permet d'atteindre des zones de code qui ne sont **pas contiguës** en mémoire. En effet, si vous vous rendez dans le `main` à l'adresse `0x12B0` puis que vous appuyez sur `espace` (pour quitter le mode "graphe"), vous verrez que l’instruction à `0x12b0` est éloignée de l’instruction à `0x12dc`.

> **Astuce IDA** : Vous pouvez utiliser le raccourcis `G` pour aller à une adresse en particulier.
{: .prompt-tip }

> **Astuce IDA** : Vous pouvez utiliser le raccourcis `espace` pour basculer du mode "graphe" vers le mode "texte" et inversement.
{: .prompt-tip }

Le fonctionnement de ce type de saut est très simple : une fois que l'instruction est exécutée, `eip` (ou `rip` en 64 bits) est **égal** à l'**adresse de destination**, là où l'exécution du programme se poursuit.

Les sauts inconditionnels se font via l’instruction `jmp`[^instr_jmp].

### Les sauts conditionnels

Là, faut rester concentré 🤓 ! Parce que des sauts de ce type, en veux-tu en voilà !

Nous avons pris le temps de bien comprendre le fonctionnement de `cmp` et `test` ainsi que les EFLAGS qui pouvaient être modifiés : ce n'est pas pour rien ! 

En fait les sauts conditionnels **dépendent** de ces deux instructions car un saut sera pris, ou non, selon les **EFLAGS modifiés** par `cmp` ou `test` (même si techniquement n'importe quelle instruction qui modifie les *flags* en question peut être utilisée).

Je vous propose de comprendre le saut où nous nous étions arrêtés (à `0x1293`) avant de voir les autres types de sauts :

![](/assets/images/introduction_au_reverse/jz_ida_bis.png)

> **Astuce IDA** : En mode "graphe", vous pouvez modifier la couleur des blocs de base en cliquant sur l'icône la plus à gauche en haut du bloc.
{: .prompt-tip }

Comme vous l'avez vu, `jz` signifie `jump if zero`, c'est-à-dire que le processeur va sauter à l'adresse de destination seulement si `ZF = 1` (ce qui signifie que les opérandes sont égales lors de la précédente instruction `cmp`).

Pour rappel la précédente instruction `cmp dword ptr [eax], 2` comparait `argc` et `2`. Or le saut ici `jz` ne s'intéresse qu'à `ZF`. Ainsi, on souhaite simplement savoir si `argc == 2` auquel cas on saute vers le **bloc vert** à l'adresse `0x12b2`. Le cas échéant, on entre dans le **bloc rouge** à l'adresse `0x1295`. 

On utilise le terme "entrer" dans le bloc rouge plutôt que "sauter" car vu que le saut `jz 0x12b2` n'est pas exécuté, le prochaine instruction est celle qui est immédiatement après `jz 0x12b2`. En passant en mode "texte" dans IDA vous pourrez bien constater que le premier bloc de la fonction `main` et le bloc en rouge sont contiguës.

De toute façon, c'est bien ce que l'on a fait dans notre code source : vérifier qu'il y a exactement deux arguments : 

![](/assets/images/introduction_au_reverse/argc_if.png)

Eh bien voilà ! Vous savez désormais comment sont gérés les `if` en assembleur ! En fait, nous avons même ici dans le code assembleur la structure d'un `if / else` bien que l'on ait pas écrit de bloc `else` dans le code : Lorsque la condition du `if` est vérifiée, on saute dans le bloc 🟢, sinon dans le bloc 🔴.

Normalement, si vous avez bien compris cet exemple vous ne devriez pas avoir trop de mal à comprendre comment fonctionnent les autres sauts conditionnels[^instr_jcc].

Par ailleurs, vous avez maintenant tous les éléments pour comprendre le code assembleur jusqu'à l'instruction à `0x12CF  call    printBin` 😎.

## 📝 Exercice : votre premier crackme

Avant d'aller plus loin, je vous propose un petit challenge de type "crackme". Le but est de trouver une **entrée valide** permettant d'afficher le message de réussite. Le programme contient pas mal de sauts, cela vous permettra de mettre en pratique vos connaissances en assembleur.

Le but est de trouver le nombre permettant d'afficher la *string* de réussite.

**L'analyse statique** à elle seule permet de trouver l'entrée valide. Vous pourrez confirmer votre résultat en exécutant le programme avec votre entrée. Il faut y aller petit à petit et bien comprendre ce qui est fait à chaque fois.

⤵️ Vous pouvez le télécharger ici : [mini_crackme](https://drive.proton.me/urls/6RYD00SWVC#wuLldDKgcoiQ).

> Les indices sont donnés en base64 afin qu'ils ne soient pas directement visible.
{: .prompt-tip }

💡 **Indice 1** : `Tidow6lzaXRleiBwYXMgw6AgdXRpbGlzZXIgdW5lIGZldWlsbGUvY2FoaWVyIGRlIGJyb3VpbGxvbiBlbiBhdmFuw6dhbnQgcGV0aXQgw6AgcGV0aXQu`

💡 **Indice 2** : `VXRpbGlzZXogbGUgdGFibGVhdSByw6ljYXBpdHVsYXRpZiBkZXMgc2F1dHMgcG91ciBjb25uYcOudHJlIGxhIGNvbmRpdGlvbiBkZSBzYXV0Lg==`

💡 **Indice 3** : `TCdlbnRyw6llIGRvaXQgw6p0cmUgc2Fpc2llIGVuIHRhbnQgcXUnYXJndW1lbnQgZW4gZMOpY2ltYWwu`

✅ **Solution** : `TGEgc29sdXRpb24gZXN0IDk1Lg==`

Une fois l’exercice terminé, on se donne rendez-vous dans la fonction `printBin` pour comprendre comment les conditions et sauts peuvent être utilisés pour réaliser des boucles 🔄.


## ℹ️ Instructions mentionnées

### 1️⃣ L'instruction `jmp dest`

#### Opérandes 
- `dest` : destination du saut. Peut être :
	- une **valeur immédiate** (exemple : adresse **relative** ou **absolue**)
	- un **registre**
	- un **pointeur**
#### Détails 

Unique instruction permettant de réaliser des **sauts inconditionnels** afin de "sauter" vers l'adresse de destination. Cela permet de pouvoir exécuter des instructions qui ne sont pas toujours situées linéairement dans le code.

> La différence entre un saut et un appel de fonction `call` est que l'on ne se préoccupe pas de sauvegarder **l'adresse de retour** afin de pouvoir y retourner plus tard.
{: .prompt-tip }

Lorsque l'opérande `dest` est une valeur immédiate, il peut s'agir d'une adresse **absolue** ou **relative** :

- adresse **absolue** : l'adresse est "**codée en dur**" dans l'opcode de l'instruction. Cela permet de sauter **plus loin** dans le code mais l'instruction prend plus de place.
	- Exemple : `e9 d8 12 00 00          jmp    0x12dd`
- adresse **relative** : seule la **différence** entre l'adresse courante de `eip` et l'adresse de destination est insérée dans l'opcode. Cela permet d'avoir des opcodes plus courts mais de sauter **moins loin**.
	- Exemple : `eb 2a                   jmp     short 0x12DC`

> Concernant les adresses absolues, elles ne sont pas insérées **tel quel** dans l'opcode. En effet, il est nécessaire de prendre en compte **la taille de l’instruction** de saut (par exemple 5 octets) avant d'insérer l'adresse de destination. C'est pourquoi l'opcode de l'exemple contient `e9 d8 12` et non pas `e9 dd 12`.
{: .prompt-tip }

Bien que le mnémonique `jmp` utilisé soit le même, il existe différentes forme où `dest` n'est pas toujours une adresse. Cela peut, en effet, être un **pointeur** ou **registre**. 

Le souci, en tant que *reverser*, est qu'il ne sera **pas toujours possible de savoir** directement vers quelle adresse le processeur va sauter lorsqu'un registre (ou pointeur) va être utilisé. En analyse statique, il sera nécessaire de déterminer les différentes valeurs que peut prendre le registre afin de trouver les **potentielles destinations**.

Le fait d'utiliser un registre comme opérande est très commun dans la modélisation des `switch` en assembleur après compilation.

#### Exemple

```nasm
jmp 0x401020
jmp rax
jmp [ebx]

```

#### Équivalent en C

Les sauts inconditionnels `jmp` sont l'équivalent de `goto` en C :

```cpp
#include <stdio.h>

int main() {
    int i = 0;

    start_loop:

    if (i < 5) {
        printf("i = %d\n", i);
        i++;
        goto start_loop;  // Sauter à l'étiquette start_loop
    }

    return 0;
}
```

### 2️⃣ L'instruction `jcc dest`

#### Opérandes 
- `dest` : destination du saut. Peut être :
	- une **valeur immédiate** (exemple : adresse **relative** ou **absolue**)

#### Détails 

`jcc` n'est **pas un mnémonique** en soi. Il s'agit d'un terme générique pour désigner le mnémonique de tous les **sauts conditionnels**. Les points communs de tous ces sauts sont les suivants :

- Ils utilisent certains *flags* parmi les EFLAGS afin de savoir s'il faut sauter
- Lorsque que le saut n'est pas exécutée, c'est l’instruction **située immédiatement après** le saut qui est réalisée
- Ils sont **précédés** d'une instruction `cmp` ou `test`

Si vous retenez ça, vous avez retenu 60% du fonctionnement des sauts conditionnels. Le reste consiste seulement à se rappeler de ce que signifie chaque mnémonique et quels *flags* sont utilisés.

Voici les principaux sauts que vous pourrez rencontrer :

> Selon le désassembleur utilisé, il peut y avoir quelques **différences** dans le mnémonique comme `jz` (*jump if zero*) qui peut être désigné `je` (*jump if equal*) mais qui représentent exactement la même instruction.
{: .prompt-tip }

| Mnémonique(s)      | Description                                    | Signe des opérations | Cas d'utilisation                   | Condition de saut     |
|-----------------|------------------------------------------------|----------------------|-------------------------------------|-----------------------|
| `jo`              | **J**ump if **o**verflow                               |                      | Détection de débordement            | `OF == 1`               |
| `jno`             | **J**ump if **n**ot **o**verflow                           |                      | Détection de débordement            | `OF == 0`               |
| `js`              | **J**ump if **s**ign                                   |                      | Tester le signe                     | `SF == 1`               |
| `jns`             | **J**ump if **n**ot **s**ign                               |                      | Tester le signe                     | `SF == 0`               |
| `jz` / `je`         | **J**ump if **z**ero / **e**qual                           |                      | Tester l'(in)égalité                | `ZF == 1`               |
| `jnz` / `jne`       | **J**ump if **n**ot **z**ero / **n**ot **e**qual                   |                      | Tester l'(in)égalité                | `ZF == 0`               |
| `jb` / `jnae` / `jc`  | **J**ump if **b**elow / **n**ot **a**bove or **e**qual / **c**arry     | Non signé            | Tester la supériorité / infériorité | `CF == 1`               |
| `jnb` / `jae` / `jnc` | **J**ump if **n**ot **b**elow / **a**bove or **e**qual / **n**ot **c**arry | Non signé            | Tester la supériorité / infériorité | `CF == 0`               |
| `jbe` / `jna`       | **J**ump if **b**elow or **e**qual / not **a**bove             | Non signé            | Tester la supériorité / infériorité | `CF == 1 \|\| ZF == 1`  |
| `jnbe` / `ja`       | **J**ump if **n**ot **b**elow or **e**qual / **a**bove             | Non signé            | Tester la supériorité / infériorité | `CF == 0 && ZF == 0`    |
| `jl` / `jnge`       | **J**ump if **l**ess / **n**ot **g**reater or **e**qual            | Signé                | Tester la supériorité / infériorité | `SF != OF`              |
| `jnl` / `jge`       | **J**ump if **n**ot **l**ess / **g**reater or **e**qual            | Signé                | Tester la supériorité / infériorité | `SF == OF`              |
| `jng` / `jle`       | **J**ump if **n**ot **g**reater / **l**ess or **e**qual            | Signé                | Tester la supériorité / infériorité | `ZF == 1 \|\| SF != OF` |
| `jg` / `jnle`       | **J**ump if **g**reater / **n**ot **l**ess or **e**qual            | Signé                | Tester la supériorité / infériorité | `ZF == 0 && SF == OF`   |

Il est à noter qu'il n'existe pas une seule manière de représenter une condition du C vers l'assembleur. Prenons par exemple le code suivant :

```cpp
unsigned int x = ...;
unsigned int y = ...;
if (x > y )
{
	// Code A
}
else
{
	// Code B
}
```

On peut très bien faire :
```nasm
cmp x, y
ja addr_code_A
code_B
```

ou :

```nasm
cmp x, y
jbe addr_code_B
code_A
```

Il faut donc être attentif lorsque l'on analyse du code assembleur pour savoir ce qui va être exécuté et sous quelles conditions.

#### Exemples
```nasm
jz 0x555555550102
jns 0x405987
```

#### Équivalent en C

Selon le **signe des variables** comparées et le **type de comparaison** utilisé, certains sauts vont être utilisés plutôt que d'autres (les différents mnémoniques d'une même instruction ont été omis par souci de concision) :

```cpp
int x = ...;
int y = ...;

if (x < 0) // js ou jns
{
	//...
}

if (x == y) //jz ou jnz
{
	//...
}

if(x < y) // jl ou jnl 
{
	//...
}

if(x >= y) // jnl ou jl
{
	//...
}

if(x <= y) // jle ou jnle
{
	//...
}

```

#### Autres formes

Il existe d'autres [sauts](http://unixwiz.net/techtips/x86-jumps.html) mais que l'on rencontre moins souvent.

## ⤴️ Notes

[^instr_jmp]: Voir ci-dessus : 1️⃣ L'instruction `jmp dest`
[^instr_jcc]: Voir ci-dessus : 2️⃣ L'instruction `jcc dest`