---
title: Partie 1 - Introduction
date: 2023-10-30 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Introduction

## Qu'est-ce que le reverse ?

Selon le bon vieux [Wikipedia](https://fr.wikipedia.org/wiki/R%C3%A9tro-ing%C3%A9nierie), la définition de *reverse* (ou rétro-ingénierie 🇫🇷) est :

```
La rétro-ingénierie, ou ingénierie inversée, est l'activité qui consiste à étudier un objet pour en déterminer le fonctionnement interne. On parle également de rétro-conception dans le domaine du vivant. Le terme équivalent en anglais est reverse engineering.
```

C'est assez concis mais peut être un peu trop vague pour cerner réellement ce qu'est le *reverse*. Je vous propose une analogie plus terre-à-terre, et j'espère que vous aimez la cuisine 👨‍🍳 !

Tout d'abord avant le comprendre ce qu'est le *reverse* en informatique, comprenons comment fonctionne globalement la programmation et compilation d'un programme.
### La réalisation d'un programme

Un programmeur, c'est finalement comme un cuisinier, il a différents ingrédients à disposition que l'ordinateur lui offre : un éditeur de texte, de la puissance de calcul, des bibliothèques prêtes à être utilisées etc.

![](/assets/images/introduction_au_reverse/ingredients.png)

En utilisant ces outils à sa disposition, il va développer le code qui n'est rien d'autre qu'une recette que l'ordinateur va compiler afin d'obtenir le programme final.

![](/assets/images/introduction_au_reverse/Recette.png)

Une fois que le code est compilé par le PC, on obtient notre programme `executable.exe` prêt à être exécuté (ou mangé si on reprend l'analogie du gâteau 😋).

![](/assets/images/introduction_au_reverse/gateau.png)

### Le chemin inverse : le reverse

Nous venons de voir **les principales étapes** de la réalisation d'un programme ( notre gâteau ) :

1. Utilisation de différents outils à disposition ↔️ Les ingrédients
2. Ecriture du code ↔️ Ecriture de la recette
3. Compilation du programme ↔️ On obtient le gâteau !

Eh bien le reverse, c'est le **chemin inverse** 🔃 de ces 3 étapes ! 

C'est-à-dire que **l'on part** du gâteau et on essaye **de déterminer les ingrédients** utilisés, la **manière** dont ils ont été cuisinés et utilisés, les **outils utilisés** etc. 

En l'occurrence certains détails peuvent se voir directement en analysant visuellement le gâteau :

- Il y a une crème marron : sûrement du chocolat
- Il y a un biscuit blanc : de la farine a été utilisée. Avec de la vanille ou des œufs ? Ou peut être du yaourt ? 
- Le haut semble plus cuit que le bas : un dysfonctionnement du four du cuistot ?

De la même manière, il est possible de réaliser **une analyse du programme** pour tenter de déterminer certaines informations basiques. C'est ce que l'on appelle **l'analyse statique**. C'est-à-dire que l'on analyse programme sans avoir à l'exécuter. C'est généralement la première étape de *reverse* sur un programme.

Vous vous en doutez, en réalisant une simple analyse statique on ne peut pas toujours avoir **toutes les informations** sur le comportement du programme. De la même manière que si l'on ne **découpe** pas le gâteau, que l'on ne le **goûte pas**, on ne pourra pas savoir si d'autre ingrédients ont été utilisés à l'intérieur, que l'on ne verrait pas de l'extérieur.

Le fait d'exécuter un programme afin de mieux l'étudier s'appelle l'**analyse dynamique**.

> Finalement, le *reverse* est le fait de partir d'un résultat et l'analyser afin d'en déduire la manière dont il a été formé.
{: .prompt-tip }

## A quoi sert le reverse ?

Le *reverse* peut être utile dans de nombreux domaines :

- Analyse de *malwares*
- Recherche et exploitation de vulnérabilités 
- *Modding*
- Émulation
- Débogage bas niveau
- Analyse *forensic*

Lors de ce cours, nous focaliserons essentiellement sur l'analyse de petits programmes basiques afin d'en comprendre le fonctionnement. Nous aurions pu également nous initier au *reverse* en nous intéressant à de la programmation IoT mais cela risque d'être plus compliqué, notamment lorsque l'on tombe sur des architectures que le PC de tout un chacun ne peut pas exécuter.

> Nous nous intéresserons à plusieurs *crackmes* lors de ce cours. Ce sont de petits programmes qui attendent un mot de passe valide pour réussir le challenge.
> 
> Ce n'est pas pour autant que ce cours est une incitation au *cracking* de jeux ou autres logiciels propriétaires !
> 
> Cela est illégal et ce n'est, comme vous le verrez, vraiment pas l'esprit de ce cours 😊.
{: .prompt-warning }

## Prérequis pour bien entamer le cours

### TL-DR 

- Savoir **programmer en C** ou au moins pouvoir comprendre un code écrit en C ( sans pour autant être un pro du C)
- Savoir **se débrouiller avec une distribution Linux**
- Savoir se **débrouiller** et ne pas baisser les bras quand on fait face à un problème
- Connaître et comprendre le **représentation binaire et hexadécimale** d'un nombre

Mais ne vous inquiétez pas, si certains **prérequis ne sont pas validés**, plusieurs **ressources** sont proposées afin que vous puissiez acquérir plus de connaissances sur ces diverses thématiques et **revenir suivre ce cours** quand vous serez fin prêts !
### Version longue

On aurait bien aimé que ce cours puisse être directement accessible à toute personne qui s'intéresse à la rétro-ingénierie mais, **malheureusement**, il y a **certains prérequis** dont il est difficile de faire abstraction.

Comme cela a été explicité précédemment, l'un des objectif du *reverse* est de comprendre comment a été développé un programme. Cela implique donc de savoir, *a priori*, **comment programmer**. 

Nous nous intéresserons principalement à des programmes **codés en C** dans ce cours. Bien que rien n'interdise le fait de faire le reverse d'application codées en Java, JS, Python etc., il faut bien faire un choix pour un cours d'introduction.

Si vous ne savez pas programmer en C, je vous conseille [ce cours](https://openclassrooms.com/fr/courses/19980-apprenez-a-programmer-en-c) de ce qui était anciennement le "Site du Zéro". Si vous le suivez et faites les exercices associés, vous devriez pouvoir vous lancer dans le *reverse* d'application en C sans trop de soucis.

Concernant les autres pré-requis : 
#### Linux

Nous allons surtout faire du *reverse* d'application développées sous Linux car cela est plus simple à compiler, analyser et modifier. De ce fait, si faire un `Hello World` en C sous Linux et le compiler, vous paraît être une mission impossible, on est mal barrés 😅 !
##### 🎒 Ressources

Je ne peux que vous recommander le cours assez complet du Site Du Zéro (Openclassrooms) permettant de s'initier à Linux : [ici](https://caron.ws/data/livre/12827-reprenez-le-controle-a-l-aide-de-linux.pdf).

> Il s'agit d'un cours qui commence à dater, il se peut que certains chapitres et certaines commandes ne soient plus d'actualité.
> 
> Mais globalement le cours est très bien fait !
{: .prompt-tip }

#### Savoir se débrouiller

Cette compétence n'est pas propre au reverse mais de manière générale dans le domaine du *hacking*, on s'attend à ce que les gens sachent faire preuve de persévérance et de patience en cherchant à résoudre les problèmes.
##### 🎒 Ressources

Travailler son mental !
#### L’hexadécimal et le binaire

Quand on s'attaque à de l'informatique bas niveau, on est souvent confrontés à des **systèmes de numération différents** de ceux que l'on connaît (base 10).

Une grande partie des valeurs, pour ne pas dire toutes, que l'on rencontre en faisant du *reverse* sont affichées en hexadécimal (base 16) et dans certains cas en binaire (base 2).
##### 🎒 Ressources 

Voici un [petit tutoriel](https://zestedesavoir.com/tutoriels/2789/les-reseaux-de-zero/annexes/binaire-et-hexadecimal-partez-sur-de-bonnes-bases/) pour comprendre l'hexadécimal et le binaire. Je vous conseille ensuite de vous **entraîner** à la main sur une feuille pour vous familiariser de plus en plus avec ces systèmes de numération.

Vous pouvez également utiliser [ce site](https://www.rapidtables.com/convert/number/hex-to-decimal.html) pour réaliser des conversions entre binaire / hexadécimal / décimal.

## A qui s'adresse ce cours

Au-delà des prérequis, ce cours s'adresse à des personnes qui souhaitent :

- comprendre comment fonctionne **concrètement** un programme
- comprendre ce que signifie **cracker** un programme
- comprendre du **code assembleur** (langage machine) et le **lien** avec le **code source**
- s'**initier** au reverse par **curiosité**, **passion** ou envie de **travailler** dans ce domaine

Ainsi, pour les personnes qui n'ont pas les prérequis pour entamer sereinement ce cours et qui sont motivées, nous leur conseillons de **prendre le temps** de bien avancer dans les **prérequis** puis de suivre ce cours afin que cela leur soit utile et qu'elles puissent apprendre facilement le *reverse*.

## 📝 Objectifs de ce cours

Les objectifs de ce cours d'introduction sont les suivants :

- Comprendre (en partie) l'**assembleur** en x86 (32 et 64 bits)
- Savoir utiliser les principaux **outils de reverse** (désassembleur, décompilateur, *debuggers*)
- Savoir utiliser les outils de reverse sous **Linux** 
- Savoir détecter et gérer quelques exemples de protections **anti-reverse** 
- Savoir mener une **analyse statique** et **dynamique**  sur programme
- Savoir résoudre des ***crackmes*** basiques

Ne seront pas abordés lors de ce cours (par souci de concision, par manque de connaissance de ma part et autre) :

- L'**exploitation détaillée** de programmes vulnérables
- Les  détails de l'assembleur des autres architectures : **ARM, MIPS, RISC-V** ... Nous nous intéresserons cependant à leurs spécificités et principales différences avec x86
- Les programmes développés en **Golang**, **Rust** et compagnie
- Le reverse sous Windows, Mac OS, Android ou iOS


