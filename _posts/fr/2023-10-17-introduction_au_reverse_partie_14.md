---
title: Partie 14 - Le décompilateur - introduction (1/3)
date: 2023-10-17 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Le décompilateur - introduction (1/3)

Chose promise, chose due 🤝 !

J'ai choisi de ne pas parler du **décompilateur** jusqu'à présent car cela pourrait en décourager certains à apprendre l'assembleur. En effet, pour des programmes assez simples on arrive à avoir, rien qu'en décompilant le programme, pas mal d'informations sur celui-ci.

A vrai dire, la différence entre un bon *reverser* et un *reverser* lambda est que le bon *reverser* sait mettre la main dans le cambouis (l'assembleur ou autre) si besoin est.

Or, si on incite les personnes intéressées par le *reverse* à se baser seulement sur la décompilation d'un programme et sur ruer vers elle, ils vont s'y habituer et lorsqu'ils s'attaqueront à des programmes de plus en plus protégés (obfusqués) et que le décompilateur leur sera (presque) d'aucune aide, ils seront bloqués 😶.

![](/assets/images/introduction_au_reverse/revers_ida_meme.png)

Mais il est vrai que c'est un **outil incontournable** dont on ne se passe guère lorsque l'on fait du *reverse* alors maintenant que l’assembleur ne vous fait plus peur 😎, nous pouvons en parler !

## Qu'est-ce qu'un décompilateur ?

Tout d'abord donnons des détails concernant le décompilateur et ce qu'il permet de faire.

Nous avons manipulé jusque-là pas mal de code assembleur issu du **désassembleur** dont le rôle est de prendre des **octets bruts** et le **convertir en assembleur** lisible par un humain.

Le **décompilateur**, lui, se situe à un plus haut niveau. Il va prendre l'**assembleur** désassemblé et tenter de le **convertir en (pseudo) code C**.

> Mais comment fait le décompilateur pour retrouver le code C initial ?
{: .prompt-info }

Tout d'abord le décompilateur ne permet pas de retrouver le même code que le code source original pour plusieurs raisons :

- les **noms des variables locales** sont perdus
- une grande partie des **symboles** est supprimée lorsque que programme est *strippé* (avec `strip` par exemple). Cela supprime les informations supplémentaires non nécessaires à l'exécution du programme, parmi elles :
	- les **noms des variables globales**
	- les **noms des fonctions**
- la forme des **structures** et des **classes** (C++) sont perdues
- certains **motifs** peuvent être décompilés de différentes manières. Par exemple, une boucle `for` devient souvent une boucle `while`.
- certaines **optimisations du compilateur** ne sont pas toujours prises en charge par le décompilateur (par exemple des divisions, modulos etc.)

Néanmoins le décompilateur apporte une chose de plus que que le code désassemblé : la **structure du code est bien plus compréhensible pour un humain**.

En fait, comme son nom l'indique, il permet de **dé-compiler**. Ainsi, s'il existe une méthodologie permettant de passer du code C à de l'assembleur (c'est la **compilation**), il est tout à fait naturel de penser qu'on devrait plus ou moins pouvoir faire le chemin inverse (c'est la **décompilation**).

### Exemple de décompilation

Je vous propose de rouvrir le programme `decimal_to_binaire` dans IDA. Une fois que c'est le cas et que vous êtes dans l'onglet du code désassemblé `IDA View` allons dans la fonction `main`. Ensuite, appuyez sur la fameuse touche de décompilation : **F5**.

![](/assets/images/introduction_au_reverse/ida_f5.png)

Vous devriez avoir un nouvel onglet `Pseudocode` qui s'ouvre : 

![](/assets/images/introduction_au_reverse/decompiled_exe.png)

Mais, c'est quasiment le code du `main` que celui de notre code source 🤩 :

```cpp
int main(int argc, char *argv[])  
{  
   if (argc != 2)    
   {  
       printf("Utilisation: %s <nombre>\n", argv[0]);  
       return 1;  
   }  
  
   int nombre = atoi(argv[1]);    
   printBin(nombre);  
   return 0;  
}
```

> **Astuce IDA** : Parfois, au lieu d'afficher une chaîne de caractères, IDA affiche un offset en mémoire plutôt que la `string` directement. Pour y remédier, aller dans `Edit`➡️ `Plugins` ➡️ `Hex-Rays Decompiler` ➡️ `Options` ➡️ `Analysis options 1` et décocher `Print only constant string literals`.
{: .prompt-tip }

> **Astuce IDA** : Il est souvent intéressant d'avoir les deux onglets désassembleur / décompilateur sur la même vue. Vous pouvez faire cela en déplaçant l'un des deux onglets. Vous pouvez ensuite synchroniser les deux vues en faisant un clic droit dans la fenêtre de décompilation et en cliquant sur `Synchronize with > IDA View`.
> 
> De cette manière, lorsque vous cliquerez sur un ligne ou que vous changerez de fonction, IDA affichera la ligne adéquate dans la fenêtre de désassemblage. 
{: .prompt-tip }

On remarque que la variable `nombre` devient `v4`. Cependant le nom de la fonction `printBin` est présent car le programme n'est pas *strippé*. Trop facile ! Et si on regardait ce qui se passe dans un programme *strippé* ?

## Analyse d'un programme *strippé*

Je vous invite à copier le programme `decimal_to_binaire` en `decimal_to_binaire_strip` puis exécuter la commande `strip decimal_to_binaire_strip`. Ensuite, ouvrez ce nouveau programme *strippé* dans IDA.

Ensuite allez dans la fonction `main`.

> Euh, mais je ne vois pas où elle est ? Elle a disparu !
{: .prompt-info }

Ah je vous avais prévenu, tous les **symboles** (noms de fonctions, noms de variables globales ...) sont **supprimés** car il n'y en a pas réellement besoin pour exécuter le programme. Lorsque le processeur exécute une fonction à l'adresse `0x401020`, qu'elle ait un nom ou pas, cela ne l'intéresse pas.

> Très souvent, les programmes que vous allez analyser seront *strippés* car cela permet d'alléger le programme mais aussi de rendre plus difficile l'analyse de ce dernier si le code n'est pas *open source* par exemple.
{: .prompt-tip }

Bon allez, je ne vous laisse pas poiroter plus longtemps et vous explique comment faire pour trouver le `main` dans un programme **ELF**.

Il faut savoir que l'exécution du `main` d'un programme **ELF** développé en C s'effectue en **3 étapes** :

1. Exécution de la fonction `start`. Le nom de cette fonction est toujours présent car le format ELF pointe vers le point d'entrée du programme qui n'est autre que cette fonction `start`.
2. Appel à la fonction `__libc_start_main` : il s'agit d'une fonction de la libc permettant de lancer correctement la fonction `main`.
3. Appel de la fonction `main`

Mais comment trouver la fonction `main` ? Tout d'abord, selon le [man](https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html) de la fonction `__libc_start_main`, son premier argument est justement l'adresse de la fonction `main`.

Dans IDA, en allant dans la fonction `start` puis en décompilant (`F5`) cette fonction on obtient ceci :

![](/assets/images/introduction_au_reverse/libc_start.png)

> **Astuce IDA** : Pour désactiver (ou réactiver) le *cast* des variables, c'est le raccourcis `Alt Gr + \`. Cela permet d'avoir du code plus lisible.
> 
> Mais attention, parfois les *casts* donnent des informations importantes, notamment lorsque l'on souhaite reprogrammer un algorithme en C, Python ou autre, il est nécessaire de faire attention à la taille des variables.
{: .prompt-tip }

On constate que le premier argument de `__libc_start_main` est `sub_127d`. Nous avons déjà vu cette **nomenclature** auparavant sous la forme `sub_OFFSET` où `OFFSET` est l'offset de la fonction dans la section `.text`. En fait, c'est tout simplement la nomenclature qu'IDA utilise lorsqu'il n'a pas le symbole (nom) de la fonction.

En l'occurrence, il s'agit de notre fonction `main` !

![](/assets/images/introduction_au_reverse/main_stripped.png)

Le binaire étant *strippé*, le nom de la fonction `printBin` n'est plus présent.

> Bah pourquoi on voit toujours certaines fonctions comme `atoi`, `printf` etc. ?
{: .prompt-info }

En fait il s'agit de **fonctions externes** qui ont été importées dans le code. D'ailleurs, si vous allez dans l'onglet `Imports` vous trouverez la liste de toutes les fonctions **importées** par le programme. Or comme il n'est pas possible de connaître à l'avance les adresses où seront chargées en mémoire ces fonctions, on s'y réfère par leur nom.

## Comment faire du *reverse* en analyse statique ?

Très souvent on est amené à faire le *reverse* d'un programme dont il manque pas mal d'informations. Il est donc nécessaire d'avoir une **stratégie globale** pour avancer petit à petit.

> Les étapes de *reverse* décrites ci-dessous sont en grande partie **subjectives**. Cela signifie qu'il ne s'agit pas forcément de la meilleure manière de faire de l'analyse statique.
{: .prompt-warning }

Comme le *reverse* peut concerner divers domaines (*malwares*, recherche de vulnérabilités, *crackmes* ...) nous allons rester dans le contexte de **résolution de *crackmes*** pour le moment. Peut-être aurons l'occasion de parler de *reverse* de *malwares* un jour, si Dieu le veut.

### Analyse préliminaire

Tout d'abord, avant d'ouvrir un programme dans IDA comme un gros bourrin, il est judicieux de consacrer un peu de temps à une analyse préliminaire d'un programme.

Cette analyse devrait permettre de répondre notamment à ces questions :

- Pour quel OS est compilé ce programme ?
	- Est-ce un ELF ? PE ? Mach-O ?
	- **Exemple d'outils** : la commande `file` 
- Quelle est l'architecture supportée ?
	- x86 ? x86_64 ? MIPS ? ARM ? ...
	- **Exemple d'outils** : la commande `file` 
- Quel est globalement le but du programme ? Comment a-t-il été conçu ?
	- **Exemple d'outils** : les commandes `strings` et `strings -el` pour afficher les strings **ASCII** et **UTF-16** du programme. Les chaînes de caractères permettent d'avoir pas mal d'informations sur un programme. Par exemple : les bibliothèques externes utilisées, leurs versions, les *strings* de réussite ou d'échec ...
	- Il est également possible de l'exécuter pour voir ce que le programme prend en entrée (saisie clavier ? fichier ? argument en ligne de commande ?)
	- La taille du fichier permet aussi d'avoir une idée de son contenu : s'il a une taille de plusieurs Mo, il peut s'agir d'un gros programme qui prendra pas mal de temps à être analysé ou bien d'un petit programme mais qui importe pas mal de bibliothèque en statique.

> Une bonne pratique avant d'exécuter un programme (principalement sous Windows) est de vérifier que le programme à étudier n'est pas malveillant, par exemple sur [Virus Total](https://www.virustotal.com/gui/) (sauf si évidemment votre but est d'analyser un *malware* dans une sandbox).
{: .prompt-danger }

### 🔎 Analyse avec un décompilateur

Une fois que l'on a une idée globale de ce que fait un programme, nous pouvons aller plus loin. Généralement en *reverse* ce que l'on veut c'est augmenter sa compréhension du code en moins de temps possible. Ainsi, on ne va pas aller dans la fonction `main` et lire les instructions assembleur une à une et modéliser la pile sur une feuille de brouillon. Ce que l'on veut c'est avoir rapidement une idée du flux d'exécution du programme en lisant le programme en diagonale.

> Lorsque l'on débute dans le *reverse* il est tout à fait normal et même recommandé de comprendre ce que font les instructions une à une et c'est ce que l'on fait depuis le début de ce cours.
> 
> Mais vous vous doutez que lorsque vous serez très à l'aise avec l'assembleur, une simple lecture en diagonale du graphe de la fonction vous permettra d'avoir une idée globale de son fonctionnement 😎.
{: .prompt-warning }

> Le graphe des blocs d'assembleur d’une fonction est très souvent appelé **CFG** (**Control Flow Graph** ou Graphe de flux de contrôle).
{: .prompt-tip }

Pour aller vite, il n'y a pas 36 000 solutions, il nous faut les outils adaptés, en particulier un : le ✨**décompilateur**✨ ! On ne va pas se mentir, lire de l'assembleur ça va 2 minutes !

Le fait d'utiliser un décompilateur va donc nous permettre de nous rapprocher le plus possible d'une analyse de code et ça, c'est plus facile pour un humain.

> Mais du coup ça ne sert à rien d'apprendre le *reverse*, l'assembleur etc. s'il suffit d'avoir les bons outils ?
{: .prompt-info }

Tout d'abord il faut savoir que l'utilisation d'un décompilateur reste dans le domaine du *reverse*. En effet, pour plusieurs raisons susmentionnées, nous n'aurons **pas le même code** que celui qui a été compilé, il va notamment falloir (en supposant que le programme est strippé):

- Renommer les **variables locales**
- Retrouver **le bon type** de chaque variable (parce que bon dire que ce sont tous des `int` 🫣 ... )
- Renommer les **fonctions**
- Retrouver le **type des fonctions** (de leur valeur de retour)
- Retrouver le **bon nombre d'argument** d'une fonction
- **Reconstituer les structures** qui sont souvent décompilées en tant que tableaux
- Ajouter des **commentaires** pour faciliter la compréhension du code

> Encore fois, la liste précédente n'est pas parfaite mais il s'agit d'une proposition de **méthodologie** lorsque l'on fait du *reverse* à partir du code décompilé.
{: .prompt-tip }

Une fois que ces différentes étapes sont réalisées, on a quasiment terminé la partie d'**analyse statique**. Il ne restera plus qu'à confirmer, si besoin, certaines hypothèses formulées lors de l'analyse statique en utilisant **l'analyse dynamique**. Lorsque cela est fait, on a généralement une bonne compréhension du programme analysé.

> Cela fait partie du job du *reverser* de savoir quand s'arrêter dans l'analyse statique: ce n'est pas parce que l'on a pas renommé et analysé toutes les fonctions du programme que l'on ne comprend pas comment il fonctionne.
> 
> Par exemple dans un *malware* qui implémente sa propre bibliothèque réseau, il n'est peut être pas nécessaire de passer du temps à reverser le *parseur* de la couche IP ou TCP ... 
> 
> Ainsi, en fonction de l'objectif du *reverse* (*forensic*, recherche de vulnérabilité, *crackmes*, analyse de *malware* ...) il va falloir définir un cadre et des objectifs à atteindre.
{: .prompt-tip }

Bien sûr ce n'est pas toujours aussi facile que ça car les programmes sensibles sont de plus en plus obfusqués par des techniques qui permettent de **freiner** l'analyser statique et/ou dynamique. Il faudra donc savoir plonger dans l'assembleur afin de le désobfusquer, par exemple, à l'aide de scripts.

Finalement ce n'est pas si mal le fait de s'être mis à l'assembleur. Voulez-vous que je vous donne une raison supplémentaire d'apprendre l'assembleur même si le décompilateur facilite le travail ? Eh bien **l'exécution dynamique** qui se fait sur un programme (en le déboguant par exemple) se fait sur l'**assembleur** et non pas sur le code compilé. 

Ainsi, une personne ne sachant pas comment sont gérées les variables locales et les arguments ne trouvera pas facilement où sont stockées les variables utilisées par le programme.
