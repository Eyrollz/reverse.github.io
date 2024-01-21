---
title: Partie 9 - Analyse statique  d'un mini-programme - fin (5/5)
date: 2023-10-22 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Analyse statique d'un mini-programme : fin (5/5)

Et si on finissait ce *reverse* de la fonction `main` qui traîne depuis pas mal de temps ? Cela nous permettra de nous attaquer à des exemples de plus en plus croustillants 👀.

Pour rappel, nous nous étions arrêtés ici :

![](/assets/images/introduction_au_reverse/main_last_time.png)

Comme vous savez désormais comment fonctionne `mov`, je vous propose de trouver par vous-même ce que font ces 4 instructions `mov` en faisant un petit schéma avec la pile d'exécution. 

C'était pas si compliqué finalement ?

Bon, on passe aux détails !

Tout d'abord l'exécution des instructions `mov [ebp+var_8], 2` et `mov [ebp+var_4], 3` va permettre de stocker les valeurs 2 et 3 dans la pile :

![](/assets/images/introduction_au_reverse/vars_loaded_bis.png)

> Nous reprenons à chaque fois les mêmes adresses dans les schémas pour que ce soit plus simple à retenir. En réalité, de nos jours, les adresses de la pile **changent** à chaque exécution.
{: .prompt-tip }

> Pas si vite ! Tu nous as dit que seules deux opérations sont possibles sur la pile : empiler avec `push` et dépiler avec `pop`. Pourquoi ici le contenu de la pile est directement modifié avec `mov` 😨 ? 
{: .prompt-info }

En fait la structure de données qu'est la pile n'est effectivement censée n'avoir que deux opérations : empiler et dépiler. Sauf que le soucis est que pour accéder aux valeurs "au milieu" de la pile, ce n'est pas évident.

J'imagine que ceux qui ont conçu les processeurs se sont accordés le droit de pouvoir accéder et modifier directement des valeurs sur la pile.

Poursuivons l'analyse : les instructions `mov     edx, [ebp+var_8]` et `mov     eax, [ebp+var_4]` vont récupérer ces valeurs depuis la *stack* pour les stocker dans les registres `edx` et `eax`.

> Mais ce ne serait pas plus simple de faire directement `mov edx, 2` et `mov eax, 3` ?
{: .prompt-info }

Oui ce serait effectivement plus simple ! Mais nous avons compilé le programme sans activer les optimisation de compilation. De ce fait, le compilateur traduit presque ligne par ligne notre fonction C qui était :  

```cpp
int main()  
{  
 int a = 2;  
 int b = 3;  
  
 return a+b;  
}
```

> Il est possible d'activer les optimisations en utilisant le paramètre `-O` avec gcc. Par exemple `gcc -O2 main.c -o exe_optimisé`.
{: .prompt-tip }

Comme nous avions créé deux variables avant de faire l'addition, le compilateur en fait de même. De plus, comme vous le savez, l'endroit de prédilection pour stocker des variables locales est la pile.

Enfin, avant l'épilogue, nous avons une dernière instruction à exécuter : `add eax, edx`.
## L'instruction `add reg_d, reg_s`

### Opérandes 
- `reg_d` : registre de destination
- `reg_s` : registre source

### Détails 

"Add" en anglais signifie "**ajouter**".

Cette instruction réalise ainsi deux actions : 
- **addition** de la valeur du registre source avec celui de destination
- **stockage** du résultat (la somme) dans le registre de destination

C'est de cette manière que sont réalisées les **additions**.

> Lorsque la somme des deux termes dépasse le plus grand entier que peut stocker le registre de destination, le résultat est tronqué pour qu'il puisse y être stocké
{: .prompt-warning }

### Exemple

Faisons la somme de `0xf0000034` et `0x20001200` :

```nasm
mov eax, 0xf0000034
mov ebx, 0x20001200

add eax, ebx ; eax = 0x10001234 et non pas 0x110001234 car le résultat est tronqué aux 32 bits de poids faible
```

### Équivalent en C

```cpp
// Initilisation des registres
int a = 0xf0000034; 
int b = 0x20001200; 

a = a + b;
```

### Autres formes

Il existe plusieurs autres formes :
- `add reg, value` 
- `add [ptr], value`
- `add reg, [ptr]`

Leur fonctionnement est toujours le même : somme des deux termes et stockage dans l'opérande de destination. 

> Toutes les instructions, sauf mention contraire (comme `lea`), déréférencent les pointeurs vers des zones mémoire.
> 
> Dans les précédentes formes, ce n'est donc pas le pointeur `ptr` qui est utilisé dans la somme mais la valeur pointée par `ptr` qui est `[ptr]` (qui serait `*ptr` en C). 
{: .prompt-warning }

## Valeur de retour

On y est presque ! Nous venons de finir l'analyse de toutes les instructions situées avant l'épilogue.

Nous pouvons donc résumé la fonction `main` (désassemblée) de la sorte :

1. Prologue
2. Stockage des variables locales
3. Copie des variables locales
4. Addition
5. Épilogue et retour

Néanmoins il manque quelque chose dont nous n'avons pas parlé. Un indice ?

```cpp
int main()  
{  
 int a = 2;  
 int b = 3;  
  
 return a+b;   // <-----
}
```

Vous voyez de quoi je veux parler 🤔 ?

> La valeur de retour ?
{: .prompt-info }

Oui c'est ça ! 

Nous avons vu que la dernière instruction exécutée avec l'épilogue est une addition. Mais nous n'avons pas vu comment est retourné le résultat (ici, la somme). Enfin si, nous en avons brièvement parlé lorsque l'on a évoqué la différence entre adresse de retour et valeur de retour.

En fait, par convention pour les programme C compilé vers x86, **la valeur de retour est toujours retournée** par `eax` (ou `rax` en 64 bits).

De ce fait, en réalisant l'addition avec `add eax, edx`, le résultat est directement stocké dans `eax` et le tour est joué !

## 📋 Synthèse

Tout d'abord félicitations pour votre premier *reverse* 😎🥳 ! Il est vrai que cela a été long car il a fallu prendre pas mal de temps pour comprendre le fonctionnement des registres, de la pile et de quelques instructions très utilisées. 

![](/assets/images/introduction_au_reverse/meme_bob.png)

Toutefois, ce précieux temps n'est pas perdu, c'est même du temps de gagné : une fois que l'on a bien saisi les fondamentaux du *reverse*/assembleur, il est bien plus facile d'apprendre de nouvelles notions, instructions etc. 

Voici un petit résumé des points abordés avant de poursuivre avec d'autres notions importantes en *reverse* :

- Les **variables locales** peuvent être accédées via un **offset négatif** par rapport à `ebp`
- Les **arguments** peuvent être accédés via un **offset positif** par rapport à `ebp`
- Il existe deux manières, ou **syntaxes**, d'afficher de l'assembleur x86 : **Intel** et **AT&T**
	- Dans la syntaxe **Intel**, la source est l’opérande de droite et la destination est l'opérande de gauche
	- Dans la syntaxe **AT&T**, c'est l'inverse
- L'instruction `mov` permet de copier des données d’une source vers une destination et dispose de 4 principales formes. Ces formes peuvent avoir quelques variantes.
- La forme `mov reg_d, [reg_p]` est principalement utilisée pour **lire** des données **depuis la mémoire**
- La forme `mov [reg_p], reg_s` est principalement utilisée pour **écrire** des données **vers la mémoire**
- L'instruction `lea` permet de réaliser des affectations de valeurs **sans déréférencement** avec la possibilité de faire de **petites opérations** directement sur l'opérande source 
- La valeur de retour d'une fonction est retournée via `eax` (ou `rax`) 