---
title: Partie 22 - L'analyse dynamique - modifier les registres et la mémoire (4/4)
date: 2023-10-09 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# L'analyse dynamique : 📝 modifier les registres et la mémoire (4/4)

Comme à l'accoutumée, après avoir appris à lire, on apprend à **écrire** ! Si vous avez bien saisi la logique lors de la lecture en mémoire, vous ne devriez pas avoir trop de soucis à la modifier.

> **Astuce gdb** : La commande `set` permet d'écrire dans des registres, variables et la mémoire.
{: .prompt-tip }

## Modifier les registres

Pour modifier la valeur d'un registre, rien de plus simple que de faire `set $reg = value` où 
- `reg` est le registre à modifier
- `value` la valeur à affecter au registre (en décimal, hexadécimal ...)

Ce qui est plutôt cool avec lorsque l'on utilise `set` avec un registre est qu'il n'y a pas besoin de spécifier la taille de `value`, il la détectera automatiquement.

Par exemple :

```
set $rdi = 0xdeadbeefcafebabe
set $eax = 0xcafebabe
```

> **Astuce gdb** : Vous pouvez utiliser `rel` (pour `reload`) afin de rafraîchir la GUI de pwndbg et voir les changements effectifs.
{: .prompt-tip }

> Si vous affectez à un registre une valeur plus petite que sa taille totale cela revient à le **mettre à zéro** d'abord (sans incidence sur les EFLAGS) **puis** à affecter la **nouvelle valeur**.
{: .prompt-warning }

### 💫 Se téléporter n'importe où dans le code

On a parfois besoin d'exécuter assez rapidement une fonction ou un bout de code sans vouloir forcément exécuter tout ce qui le précède. Par exemple, si on souhaite analyser une fonction critique d'un *malware* mais qu'elle est précédée d'une fonction qui détecte le débogage, il vaut mieux éviter de l'exécuter.

Il existe deux manières de se ~~téléporter~~ **déplacer** dans le code :

1. La commande `jump 0xdest`
2. Modifier `eip`/`rip` avec `set`. Exemple : `set $rip = 0x55555555abcd`

La différence entre les deux est la suivante :

1. Avec `jump`, le processeur saute à l'adresse indiquée et **poursuit l'exécution** 
2. En modifiant `eip` ou `rip`, le processeur saute à l'adresse indiquée mais **ne poursuit pas** l'exécution

Ainsi, à moins d'avoir une raison valable d'utiliser `jump`, il vaut mieux **modifier le pointeur d'instruction** pour mieux contrôler le flot d'exécution. 

## Modifier une zone mémoire

Pour modifier une zone mémoire pointée par une adresse, nous allons également utiliser `set`.

Compilons le code ci-dessous afin de voir comment nous allons réussir à modifier la mémoire :

```cpp
#include "stdio.h"  
#include "string.h"  
#include "stdlib.h"  
  
int main()  
{  
 unsigned long long *identifiant = malloc(8);  
 memset(identifiant, 0xff,8);
  
 if(*identifiant == 0xdeadbeefcafebabe)  
   puts("Connexion en tant qu'administrateur !");  
 else  
   puts("Connexion refusée.");  
  
 return 1;  
}
```

Il s'agit d'une vérification à deux balles permettant d'autoriser la connexion à un administrateur et la refuser pour les autres.

Evidemment, en exécutant normalement le programme, il est **impossible** de se connecter en tant qu'admin car notre identifiant sera toujours `0xffffffffffffffff`. Mais en tant que *reverser*, nous n'allons pas nous laisser abattre par une aussi simple protection d'authentification 😈 !

Compilons le programme en 64 bits. Ouvrons-le dans gdb et mettons un point d'arrêt dans le `main` puis exécutons le programme.

Maintenant que vous savez exécuter pas à pas un programme, allez jusqu'à l'instruction de comparaison avec `0xdeadbeefcafebabe` **sans l'exécuter** :

![](/assets/images/introduction_au_reverse/before_cmp.png)

La variable `identifiant` est contenue dans l'adresse pointée par le registre `rax`.

> **Astuce gdb** : Pour modifier une zone mémoire pointée par un registre, il est possible d'utiliser `set *$reg = value`.
> 
> Pour modifier directement les données pointées par une adresse : `set *0xaddr = value`.
{: .prompt-tip }

Modifions cette valeur avec la commande `set *$rax = 0xdeadbeefcafebabe`.

> Veillez à bien précéder le registre d'un astérisque `*` afin que ce soit la valeur pointée qui soit modifiée et non pas le contenu du registre, comme cela a été fait plus haut.
{: .prompt-tip }

En exécutant `rel`, on constate que la valeur de `rax` est `0xffffffffcafebabe` et ce n'est pas ce que l'on voulait faire ... 

En fait, ce qui se passe est que gdb modifie **au plus 4 octets** dans la mémoire car il considère que ce qui est pointé est, par défaut, un `int`. C'est pourquoi les 4 octets de poids fort pointés par `rax` n'ont **pas été modifiés**.

Nous devons donc spécifier **le type** afin que gdb sache qu'il s'agit d'une variable de 8 octets à modifier `set {unsigned long long}$rax = 0xdeadbeefcafebabe`. 

> **Astuce gdb** : De la même manière, si vous ne souhaitez modifier qu'un seul octet (au lieu de 4 par défaut) vous devez le spécifier. Exemple : `set {byte}0x401020 = 0xf5`.
{: .prompt-tip }

Par ailleurs, nous aurions pu également manipuler directement l'adresse contenue dans `rax` pour effectuer cette modification en mémoire `set {unsigned long long}0x5555555592a0 = 0xdeadbeefcafebabe`

> Vous remarquerez que lorsque l'on spécifie le type de la zone mémoire, il n'y a plus besoin de mettre l'astérisque `*`.
{: .prompt-tip }

A présent que nous avons modifié la mémoire pour y mettre l'identifiant de l'administrateur, nous pouvons poursuivre l'exécution du code :

![](/assets/images/introduction_au_reverse/connected_as_admin.png)

Voilà voilà 😎 !

> Savoir modifier la mémoire d'un processus dans un débogueur est une chose très importante. Cela permet notamment de contourner des détections basiques de débogage sans avoir à modifier le code du programme.
{: .prompt-tip }

## 📋 Synthèse

En somme, l'analyse dynamique met à disposition d'un *reverser* des fonctionnalités lui permettant de **manipuler** un programme avec la **granularité** qu'il souhaite.

Cela permet notamment d'analyser des spécificités du code qui n'apparaissent pas forcément de prime abord lorsque l'on **analyse statiquement** un programme.

Encore une fois, il ne s'agit pas de **choisir** entre **analyse statique** et **dynamique** pour bien comprendre un programme : il faut savoir tirer partie des avantages des deux.

Ainsi, on ne s'attardera pas en analyse statique sur une fonction compliquée et qui semble peu intéressante alors qu'il est possible de l'exécuter plusieurs fois avec des arguments différents pour avoir une idée de ce qu'elle fait en fonction de la valeur de retour.

Egalement, nous n'avons pas vu toutes les fonctionnalités que propose **gdb** et **pwndbg**. Ce serait beaucoup trop long et pas vraiment pédagogique de voir dans ce cours tout ce qu'ils proposent. Ainsi, si vous souhaitez aller plus loin dans ces fonctionnalités, vous pouvez toujours lire leur documentation.

Vous trouverez facilement sur internet des fiches de synthèses (ou *cheat sheets*) résumant les principales commandes de gdb comme [celle-ci](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf). Encore une fois, les **annexes** de ce cours regroupent les différentes astuces et commandes gdb vues ensemble.

Enfin, nous avons parlé exclusivement de gdb car nous nous sommes focalisés sur l'analyse de programme ELF. En revanche, si vous souhaitez faire de l'analyse dynamique sous **Windows**, vous pouvez utiliser **x64dbg** qui est un débogueur très puissant et très utilisé sous Windows.