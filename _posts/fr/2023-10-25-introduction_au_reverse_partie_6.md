---
title: Partie 6 - Analyse statique  d'un mini-programme - les registres (2/5)
date: 2023-10-25 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Analyse statique  d'un mini-programme  :  les registres (2/5)

Nous en avons déjà parlé brièvement aux précédents chapitres en disant qu'il s'agit d'une sorte de petite zone mémoire située dans le processeur. Cela a l'**avantage** de ne pas avoir à accéder à la RAM qui est située plus loin et donc d'avoir des performances plus élevées. L'**inconvénient** c'est qu'il n'y a pas tant de registres que ça.

A titre de comparaison, de nos jours les **RAM** ont une capacité de **8 Go** minimum alors que le total de mémoire représenté par tous les **registres** du processeur ne dépasse même pas **1 Mo** 🥶.

## Les principaux registres

Je vous propose de nous intéresser aux principaux registres en 32 bits avant d'élargir notre vision vers les registres 64 bits et les registres "secondaires".

| Nom du registre | Taille en bits | Utilisation usuelle |
|-----------------|----------------|---------------------|
| `eax`             | 32             | Stocker la valeur de retour d'une fonction                    |
| `ebx`             | 32             | Utilisations diverses                    |
| `ecx`             | 32             | Utilisé en tant que compteur dans les boucles                     |
| `edx`             | 32             | Utilisé lors des multiplications et divisions                    |
| `edi`             | 32             | Utilisé comme pointeur vers une zone mémoire de destination                    |
| `esi`             | 32             | Utilisé comme pointeur vers une zone mémoire source                    |
| `ebp`             | 32             | Utilisé comme pointeur vers la base de la pile                    |
| `esp`             | 32             | Toujours utilisé comme pointeur vers le haut de la pile                    |
| `eip`             | 32             | Toujours utilisé comme pointeur vers l’instruction courante exécutée                    |

Bien que la plupart de ces registres aient **un usage prédisposé**, généralement c'est un peu plus souple que cela sauf pour certains registres :

- `esp` est toujours utilisé pour pointer vers la pile (plus précisément le **haut de la pile**)
- `eip` est toujours utilisé pour pointer vers l'adresse de **l’instruction courante**
- `eax` contient quasi systématiquement la **valeur de retour** mais cela ne l'empêche pas de pouvoir être utilisé autrement (stockage, multiplication, division ...)

Par exemple, il est possible qu'une fonction, le temps d'un calcul, utilise `ebp` comme registre de stockage temporaire, rien ne l'interdit.

Néanmoins, `ebp` et `esp` vont être très souvent utilisés pour gérer le stockage et l'accès aux **arguments** et **variables locales** situées dans la pile. Nous verrons cela en détails au prochain chapitre.

## Les différentes tailles de registres

Si vous n'avez pas la mémoire trop courte, vous vous souvenez que pour avoir la version 64 bits d'un registre, il suffit de changer le `e` de début par un `r` et inversement.

En fait, en assembleur x86, il est possible d'utiliser différentes tailles pour un même registre selon ce que l'on souhaite faire. Par exemple, si je souhaite stocker un `char` dans le registre `eax`, je n'ai besoin que d'un octet (8 bits) : je n'aurai donc pas besoin de tous les 32 bits ou 64 bits qui sont présents dans le registre.

Ainsi, il est possible de manipuler les parties basses des registres lorsque l'on a pas besoin d'utiliser les bits de poids fort. Par exemple, voici les différents noms des "sous-registres" de `rax` :

![](/assets/images/introduction_au_reverse/rax_decomp.png)

> `AH` représente les 8 bits de poids fort (*High*) de `AX`
> `AL` représente les 8 bits de poids faible (*Low*) de `AX`
{: .prompt-tip }

Ainsi, voici où pourraient être stockées certaines variables :

- `long long int` ➡️ `rax` (64 bits seulement)
- `int` ➡️ `eax`
- `short` ➡️ `ax`
- `char` ➡️ `al`

> Ce n'est pas parce qu'une valeur est de petite taille que l'on ne peut pas la stocker dans un registre de grande taille !
>
> Evidemment l'inverse, par contre, n'est pas possible ⛔.
{: .prompt-warning }

Voici les différents noms des principaux registres en fonction des différentes tailles :

| 64 bits | 32 bits | 16 bits | 8 bits (poids fort) | 8 bits (poids faible) |
|---------|---------|---------|---------------------|-----------------------|
| `rax`     | `eax`     | `ax`      | `ah`                  | `al`                    |
| `rbx`     | `ebx`     | `bx`      | `bh`                  | `bl`                    |
| `rcx`     | `ecx`     | `cx`      | `ch`                  | `cl`                    |
| `rdx`     | `edx`     | `dx`      | `dh`                  | `dl`                    |
| `rdi`     | `edi`     | `di`      | -                   | `dil`                   |
| `rsi`     | `esi`     | `si`      | -                   | `sil`                   |
| `rbp`     | `ebp`     | `bp`      | -                   | `bpl`                   |
| `rsp`     | `esp`     | `sp`      | -                   | `spl`                   |
| `rN`      | `rNd`     | `rNw`     | -                   | `rNl`                   |

Dans le précédent tableau, `N` dans les registres `rN` représente un nombre entre 8 et 15, par exemple : `r8`,`r9`,...,`r15`. Il s'agit de registres présents et utilisables uniquement dans les processeurs **x86_64**.

> Ce tableau n'est pas à apprendre par cœur mais il est important de garder en tête la "logique" utilisée dans la nomenclature des registres .
> 
> On revient souvent vers ce tableau, par exemple, lorsque l'on ne se rappelle plus si `dl` représente l'octet de poids faible de `edx` ou `edi` ?
{: .prompt-tip }

> Pourquoi `eip` ou `rip` ne sont pas présents dans le tableau ?
{: .prompt-info }

Comme nous l'avions dit tout à l'heure, `eip` pour les programmes 32 bits ou `rip` pour les programmes 64 bits pointent vers l'adresse de **l'instruction courante**. Ainsi, cela n'a pas tellement de sens d'avoir accès aux bits de poids faible dans un tel contexte.

## Les autres registres

### Le registre EFLAGS

**EFLAGS** (ou **RFLAGS** en 64 bits) est un registre un peu spécial.

Contrairement aux registres vus précédemment, nous n'allons pas l'utiliser pour y stocker des données ou le faire pointer vers une zone mémoire. Il s'agit d'un registre où chacun de ses bits a une **signification particulière** et représente un **état** bien précis du processeur. On parle également de *flags* de la même manière que l'on parle de *flags* en C lorsque l'on manipule une variable du type `ENUM1 | ENUM2 | ENUM3` ... 

C'est-à-dire que chaque *flag* correspond à un bit à une position bien déterminée. Chacun de ces *flags* (ou bit si vous préférez) va être modifié dans **certaines circonstances**. Selon leur valeur, `1` ou `0`, cela va apporter une indication sur le code qui est exécuté.

> Les registres `EFLAGS` et `RFLAGS` n'ont rien à voir 🙅‍♂️ avec les [variables](https://fr.wikipedia.org/wiki/CFLAGS) `CFLAGS` utilisées lors de la compilation. 
{: .prompt-warning }

Prenons le *flag* `ZF` qui est l'un des plus connus. Lorsqu'une opération impliquera un résultat nul, par exemple une soustraction entre deux termes égaux, `ZF` sera égal à 1. Tandis que lorsque le résultat sera non nul, `ZF` sera nul. Ça va vous me suivez 😅 ?

C'est ce *flag* qui est généralement utilisé lorsqu'une condition de type est rencontrée :

```cpp
if(var)
{
	// Code exécuté si "var" est non nulle
}
else
{
	// Code exécuté si "var" est nulle
}
```

Voici, selon [Wikipedia](https://fr.wikipedia.org/wiki/RFLAGS), la position des différents *flags* dans `RFLAGS` :
![](/assets/images/introduction_au_reverse/rflags.png)

Les bits grisés étant réservés et/ou dont l'utilité est inconnue.

Voici l'utilité des principaux `flags` des `RFLAGS`: 

- **ZF (Zero Flag)** : le *flag* `ZF` est mis à 1 si le résultat d'une opération est zéro, et à 0 sinon. Il est notamment utilisé pour les comparaisons.
- **CF (Carry Flag)** : le *flag* `CF` est mis à 1 si une opération génère une retenue ou emprunte à une opération précédente, et à 0 sinon. Il est principalement utilisé dans les opérations arithmétiques.
- **SF (Sign Flag)** : le *flag* `SF` est mis à 1 si le résultat d'une opération est négatif et à 0 sinon. Il indique le signe du résultat.
- **OF (Overflow Flag)** : le *flag* `OF` est mis à 1 si une opération arithmétique génère un dépassement de capacité (*overflow*) et à 0 sinon. Il est utilisé pour détecter des erreurs lors de l'ajout ou de la soustraction de nombres signés (pouvant être positifs ou négatifs).
- **PF (Parity Flag)** : le *flag* `PF` est mis à 1 si le nombre de bits définis à 1 dans le résultat est pair, et à 0 si le nombre de bits définis à 1 est impair.
- **IF (Interrupt Enable Flag)** : le *flag* `IF` est utilisé pour activer (à 1) ou désactiver (à 0) les interruptions matérielles. Quand il est à 0, les interruptions matérielles sont désactivées.
- **TF (Trap Flag)** : le *flag* `TF` est utilisé pour activer (à 1) ou désactiver (à 0) le mode de débogage de trace, où le processeur génère une interruption après chaque instruction.

Nous verrons bien en détails l'utilité de ces *flags* lorsque l'on verra comment sont modélisées **les conditions** (`if`,`else` ...) en assembleur.
### Les registres AVX

Les registres **AVX** (Advanced Vector Extensions) sont des registres **supplémentaires** qui ont été ajoutés au fur et à mesure à l'architecture x86.

Ils permettent le **traitement simultané de plusieurs données** en parallèle, ce qui est particulièrement utile dans les applications impliquant des calculs intensifs, tels que le traitement d'images, le rendu 3D, la simulation physique, etc. AVX étend les capacités **SIMD** (Single Instruction, Multiple Data) des processeurs x86 en introduisant des **registres plus large**s et en permettant des opérations vectorielles sur des données de **128 bits**, **256 bits** et même **512 bits**.

Leur usage n'est pas seulement destiné à de l'utilisation avec de l'image ou de l'audio, mais ils peuvent être utilisés pour, par exemple, mettre à zéro une grande portion de mémoire ou stocker des valeurs nécessitant beaucoup de place.

Les registres **AVX** ont la taille suivante :

- **XMM** : 128 bits (16 octets)
- **YMM** : 256 bits (32 octets)
- **ZMM** : 512 bits (64 octets)

Ils sont agencés de cette manière (où `n` est un nombre entre 0 et 31):

| [511 ; 256] | [255 ; 128] | [127 ; 0] |
|-------------|-------------|-----------|
| ZMMn        | YMMn        | XMMn      |

Si vous ne savez pas les utiliser, ce n'est pas bien grave car on ne les rencontre pas si souvent que ça. Et lorsque c'est le cas, il suffit de lire la *doc'* pour comprendre comment cela fonctionne. 

Et puis, vous savez quoi ? Apparemment même Intel (oui oui ceux qui font les processeurs Intel et l'assembleur x86 associé) n'a pas su les utiliser avec le codec **AV1** 😅 ([source](https://youtu.be/Kv4FzAdxclA?feature=shared&t=960)).

## 📋 Synthèse

Nous avons vu les principaux registres en x86. Il y en a d'autres mais qui ne sont pas souvent utilisés en *reverse* tels que les registre `CR0`, `CR1` etc. qui sont utilisés en *kernel land*.

Néanmoins nous avons vu la majorité de ceux qui sont utilisés en *user land*, c'est-à-dire dans les programmes usuels qui ne sont pas exécutés directement en mémoire *kernel land* (donc pas les pilotes, modules *kernel* ...).

Nous avons vu ensemble que les registres peuvent contenir des **données quelconques** mais peuvent aussi être utilisés en tant que **pointeurs** (comme `rbp`). En effet, nous verrons un peu plus loin ce que cela implique en termes d'instructions assembleur car on n'utilise pas les mêmes instructions selon que le registre pointe vers une adresse ou non.