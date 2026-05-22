---
title: Partie 1 - Introduction
date: 2026-05-08 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

Au nom de Dieu, le Tout Miséricordieux, le Très Miséricordieux.

# Introduction

Bienvenue dans ce nouveau cours d'introduction au **pwn** ! 

Nous voilà enfin dans ce cours qui permettra, on espère, **d'éclaircir** ce domaine souvent considéré comme **ésotérique** ou **réservé à une élite**. 

Initialement, nous avions prévu d’y inclure une grande partie dédiée à l’exploitation dans le tas (*heap*). Finalement, afin de rendre l’ensemble plus digeste et plus simple à suivre, nous avons choisi de séparer ces sujets en **deux cours distincts** :

1. ce cours consacré aux bases du **pwn** et à l’**exploitation dans la pile** ;
2. un second cours entièrement dédié à l’**exploitation dans le tas**.

> Pour rappel, le tas (ou *heap*) est la zone mémoire qui permet **d'allouer dynamiquement** de la mémoire avec `malloc`, `new`, etc.
{: .prompt-tip }

Cette séparation nous permettra d’aller plus loin sur chacun des sujets sans surcharger inutilement l’introduction au *pwn* 😉.

## Qu'est-ce que le pwn ?

Comme à l'accoutumée, jetons un œil à l'origine du terme anglais *pwn*.

En français, on pourrait désigner le *pwn* (à prononcer "pone") comme étant de **l'exploitation de binaires**. La première utilisation du mot *pwn* est débattue mais cela semble venir d'une typo du mot anglais *own* qui signifie, selon le contexte, **dominer**, **avoir le dessus sur** etc.

Ainsi, le *pwn* consiste à **tirer avantage de vulnérabilités** présentes dans un programme en les exploitant, généralement pour réaliser une **exécution de code** arbitraire, souvent, afin d'aboutir à une **élévation de privilèges**. Finalement, cela revient à de la **recherche de vulnérabilités** ainsi que la mise en place de l'**exploitation** des failles trouvées.

> Par abus de langage, on désigne par **binaire** un programme compilé (ex: fichier au format [ELF](https://reverse.zip/posts/introduction_au_reverse_partie_3/#le-format-elf), PE ...) 
{: .prompt-tip }

La recherche de vulnérabilités est principalement utilisée de deux manières :

- 🛡️ **défensivement** : la recherche de vulnérabilités est réalisée sur des produits (programmes, OS ...) afin de corriger les failles trouvées. Cela peut se faire en interne (ex: département de recherche de vulnérabilités) ou en externe (ex: *bug bounty*).
- ⚔️ **offensivement** : la recherche de vulnérabilités peut aussi être utilisée pour vendre des exploits, compromettre illégalement une infrastructure ou s'attaquer à une personne en particulier 😞 ...

> Le *pwn* fait partie de la recherche de vulnérabilité mais toute recherche de vulnérabilité n'est pas forcément du *pwn*. 
> 
> A titre d'exemple, on parle plutôt de *pentest* lorsqu'il s'agit de trouver des vulnérabilités sur des applications/interfaces **web**.
{: .prompt-tip }

## 📝 Objectifs de ce cours

Pour ne pas que ce cours devienne un amas d'informations totalement **abstraites** 😴, nous allons nous efforcer de **mettre en pratique** ce que nous voyons ensemble afin que chacun puisse mettre les mains à la pâte et constater de lui-même ce qu'il a bien compris et ses lacunes.

Ainsi, plusieurs **challenges** seront proposés pour s'exercer et monter petit à petit en compétence.

Les objectifs de ce cours d'introduction sont les suivants :

- comprendre les **principales vulnérabilités** dans les binaires (*buffer overflow*, attaque via *format string*) ;
- comprendre les **concepts sous-jacents** permettant l'exécution de code arbitraire   (contrôle de `rip`, corruption de pointeur de fonction, gestion de la *stack* ...) ;
- savoir mettre en place les principales **méthodes d'exploitation** en **x86_64** (*shellcode*, ret2libc, ROP, pivot de *stack* ...) ;
- se familiariser davantage avec un **débogueur** et un **décompilateur** ;
- savoir utiliser [pwntools](https://github.com/Gallopsled/pwntools) pour communiquer en Python avec un programme et déployer son exploit.

A la fin de ce cours, vous devriez avoir tous les éléments pour comprendre comment [ce speedrun](https://www.youtube.com/watch?v=FkQdwUns7H8) de Super Mario World [fonctionne](https://www.youtube.com/watch?v=vAHXK2wut_I) 😎.

Ne seront pas abordés lors de ce cours (par souci de concision, par manque de connaissance de ma part etc.) :

- le *pwn* sous Windows (bien qu'il y ait pas mal de similitudes avec le *pwn* sous Linux) ;
- le pwn avec d'autres architectures (ARM, MIPS, RISC-V ...) ;
- l'exploitation en *kernel land* ;
- la multitude d'attaques possibles dans le tas de manière exhaustive (tous les **house of xxxx** pour les connaisseurs).

> Comme pour le reste des ressources présentes sur ce site, il n'est en aucun cas question d'apprendre à exploiter des programmes sur des machines qui nous sont **interdites d'accès**, ce qui est 🚫 **illégal** 🚫.
{: .prompt-danger }

Ce que je vous propose est d'analyser chronologiquement les différentes vulnérabilités et contre-mesures. Nous utiliserons cette excellente frise chronologique comme support ([source](https://web.archive.org/web/20220810171253/https://www.hoppersroppers.org/roadmap/training/pwning.html)) :

![](/assets/images/introduction_au_pwn/pwn_timeline.png)

Vous avez :
- **En haut** 😈 : les vulnérabilités et méthodes d'exploitations
- **En bas** 🛡️ : les contre-mesures

Nous n'aurons malheureusement pas le temps d'aborder toutes ces **vulnérabilités** et **contre-mesures** mais nous nous intéresserons aux **principales**. Ce qui est intéressant en apprenant à **contourner les protections** de manière **chronologique** est que l'on commence avec des exploits assez **faciles** à mettre en place puis nous complexifions l'exploitation en ajoutant différentes protections qui ont vu le jour au fil du temps. 

De cette manière, d'un exploit à un autre, vous ne serez pas totalement dépaysés et vous comprendrez les **avantages** d'une technique par rapport à une autre.

## Comprendre, c'est bien. Pratiquer, c'est mieux

Ce cours ne contiendra pas seulement les aspects théoriques liés au *pwn*. En effet, de nombreux exercices et challenges vous attendent. Néanmoins, cela ne sera pas suffisant en termes de pratique et vous voudrez sûrement aller plus loin. 

Voici quelques plateformes qui pourront vous être utiles dans votre progression :

- 🇫🇷 [Root Me](https://www.root-me.org/?lang=fr) : on ne présente plus cette plateforme de challenges. Elle dispose d'une catégorie *pwn* avec des challenges divers et variés, que ce soit en termes de complexité, de résolution ou de technique d'exploitation. De plus, un serveur Discord est disponible dans le cas où vous ne souhaitez pas vous sentir seul ou que vous êtes bloqués dans un challenge. Ce qui est pas mal avec cette plateforme est qu'il existe beaucoup de challenges de niveau débutant.
- 🇫🇷 [Hackropole](https://hackropole.fr/fr/) : une autre plateforme française qui gagne en popularité. Il s'agit d'un site qui regroupe tous les challenges qui ont pu être présentés lors du FCSC. La plateforme dispose également d'une catégorie *pwn* avec des challenges très diversifiés où il faudra très souvent sortir de votre zone de confort. C'est l'une des meilleures méthodes pour apprendre à se débrouiller et sortir des sentiers battus ;
- 🇬🇧 [W3Challs](https://w3challs.com/) : une plateforme assez ancienne mais qui est toujours fonctionnelle et accessible. Il existe une catégorie *pwning* pour tenter d'exploiter les programmes proposés. Le site dispose également d'un forum mais qui ne semble plus trop être fréquenté 😅 ;
- 🇬🇧 [OverTheWire](https://overthewire.org/) : la plateforme possède plusieurs catégories de challenges et notamment des challenges d'exploitation de binaires. Le seul défaut de la plateforme est qu'il n'y a, apparemment, pas de forum ou de serveur Discord ;
- 🇬🇧 [pwn.college](https://pwn.college/dojos) : il s'agit d'une plateforme assez récente qui propose pas mal de contenu orienté *pwn*. Je ne l'ai jamais essayée mais elle semble être accessible pour débuter. Il y a même un serveur Discord.

Voici d'autres sites mais que je n'ai pas eu l'occasion de tester :

- 🇬🇧 [pwnable.kr](https://pwnable.kr/#) ;
- 🇬🇧 [pwnable.tw](https://pwnable.tw/) ;
- 🇬🇧 [pwnable.xyz](https://pwnable.xyz/) ;
- 🇬🇧 [exploit.education](https://exploit.education/) ;
- ...

Le fait de jongler entre **le cours et les challenges** est une **très bonne méthode** pour **progresser**.

Autre point important : ce cours n'est **pas à lire linéairement** dans le but d'arriver au dernier chapitre le plus rapidement possible. L'objectif est que vous ayez **accès à des explications théoriques** ainsi qu'à quelques **exercices/challenges** vous permettant de mettre en application ce qui a été appris. Cela vous permettra, le jour où vous en aurez besoin, de venir **relire tranquillement** un ou plusieurs chapitres.

Ainsi, n'hésitez pas à faire une pause dans le cours à un moment donné pour **passer plus temps à pratiquer** ou tout simplement **faire autre chose** car à force d'acquérir de nouvelles informations le cerveau sature et a besoin de temps pour les assimiler.

Vous remarquerez aussi que certains chapitres, notamment ceux liés à l'exploitation dans le tas, sont parfois **très détaillés**. Or ces détails pourront être d'intérêt pour les uns comme ils pourront paraître superflus pour d'autres. En somme, à vous de voir jusqu'à quel degré de détail vous souhaitez aller.

## 🏆 Challenges et exercices

Plusieurs **exercices** et **challenges** sont disponibles dans ce cours. Bien que chacun d'eux puisse être réalisé grâce à un **conteneur Docker fourni**, nous vous recommandons vivement d'avoir à portée de main une machine virtuelle **Ubuntu 24.04** qui est la distribution où tous les exercices et challenges fonctionnent.

Nous avons également mis à votre disposition [une page annexe](/posts/introduction_au_pwn_partie_30) qui contient les **instructions et informations générales** concernant les exercices/challenges sous forme de conteneurs Docker.

Les **conteneurs Docker** permettent d’exécuter les exercices et les exemples du cours dans un environnement **clé en main**, sans dépendre de la configuration de votre machine.  Cela assure que les comportements observés et les vulnérabilités exploitées seront les mêmes pour tout le monde.

## 📋 Prérequis pour bien entamer ce cours

On aurait bien aimé que ce type de cours puisse être accessible à tout un chacun. Malheureusement, il s'agit d'un cours qui nécessite tout de même quelques **connaissances au préalable** 🤓. 

En effet, pour chercher des vulnérabilités, il est nécessaire **d'une part** de comprendre le fonctionnement d'un binaire, **d'autre part**, d'être assez à l'aise techniquement parlant pour y trouver des vulnérabilités. 

Ajoutés à cela les connaissances nécessaires pour exploiter lesdites vulnérabilités : ce n'est chose aisée lorsque l'on part de 0.

### TL-DR 

- Savoir **programmer en C** ou au moins pouvoir comprendre un code écrit en C (sans pour autant être un pro du C) ;
- Être à l'aise en **reverse** dans la compréhension de **l'assembleur x86** ;
- Savoir utiliser de manière basique un **débogueur** et un **décompilateur**/**désassembleur** ;
- Savoir **se débrouiller avec une distribution Linux** ;
- Savoir se **débrouiller** et ne pas baisser les bras quand on fait face à un problème.

### Version longue

Si vous ne remplissez pas un de ces prérequis, pas de panique, il y a des **ressources** disponibles et ce n'est qu'une question de temps avant que vous puissiez revenir ici et démarrer ce cours.

#### Programmer en C

Il n'est pas demandé d'avoir un niveau de pro en C et d'avoir passé des années et des années à programmer dans ce langage. Néanmoins, il est nécessaire d'avoir les bases et comprendre de quoi on parle lorsque l'on **lit du code décompilé**.

Étant donné que l'on n'aura pas le temps de nous attarder sur les notions du C que nous verrons lors de ce cours (structures, variables globale, mémoire dynamique, pointeur de fonction, types de données ...), il est important de les connaître en amont.

##### 🎒 Ressources

Nous sommes (presque !) tous passés par le [fameux cours de C](https://openclassrooms.com/fr/courses/19980-apprenez-a-programmer-en-c) du Site Du Zéro (actuellement OpenClassrooms) qui aborde ce langage de programmation avec pédagogie. En le suivant et en vous exerçant vous n'aurez pas de difficulté à comprendre les différents bouts de code C que nous rencontrerons. 

#### Être à l'aise en reverse

L'exploitation de vulnérabilités demande souvent, voire systématiquement, de lire le code assembleur du programme avant de savoir comment adapter son exploit. Il est donc important de pouvoir **comprendre du code assembleur x86_64**.

De plus, dans les challenges de *pwn*, nous avons **rarement accès** au code source. Nous sommes donc très souvent confrontés à une étape préalable de *reverse* afin de **comprendre le programme** avant d'y rechercher des vulnérabilités.

Vous n'êtes pas obligés d'être des cracks en *reverse* qui comprennent instantanément ce que fait un programme en lisant l'assembleur (perso je ne sais pas le faire 😅). Ce qu'il faut connaître pour ne pas être perdu sont les choses suivantes :

- savoir lire de l'assembleur et ne pas avoir de mal à comprendre de nouvelles instructions ;
- connaître les principaux registres x86/x86_64 et leur utilité ;
- le fonctionnement de la pile ;
- le fonctionnement des différents types de variables (variables locales, globales, tableau, pointeurs, structures ...) ;
- savoir utiliser un débogueur et un décompilateur/désassembleur.

##### 🎒 Ressources

Ça tombe bien, vous êtes au bon endroit !

Nous avons un cours sur le site pour [apprendre le reverse](https://reverse.zip/categories/introduction-au-reverse/). Si vous suivez ce cours jusqu'à la fin, vous devriez avoir le niveau en termes de rétro-ingénierie pour entamer ce cours.

Si vous estimez ne toujours pas être à l'aise en *reverse*, n'hésitez pas à faire quelques *crackmes* pour consolider vos connaissances.

#### Linux

Nous allons nous intéresser lors de ce cours aux programmes ELF. Ainsi, nous allons souvent compiler, patcher, exécuter des programmes **sous Linux**. Il est donc important de savoir réaliser ces tâches sans y perdre trop de temps.

De plus, lors de l'exploitation des binaires, nous serons confrontés à des **mécanismes de sécurité présents sous Linux** (permissions, possession ...) qu'il est bon de connaître pour ne pas être déboussolé.

Par ailleurs, nous allons procéder à des installations d'outils dont certains seront peut-être à compiler, d'autres dont la modification de fichiers de configuration sera requise. Ainsi, en fonction de votre distribution, de votre configuration etc., il est possible que vous ayez à mettre la main dans le cambouis pour faire en sorte de réussir l'installation d'un outil ou d'un programme.

##### 🎒 Ressources

Je ne peux que vous recommander le cours assez complet du Site Du Zéro (Openclassrooms) permettant de s'initier à Linux : [ici](https://caron.ws/data/livre/12827-reprenez-le-controle-a-l-aide-de-linux.pdf).

> Il s'agit d'un cours qui commence à dater, il se peut que certains chapitres et certaines commandes ne soient plus d'actualité.
> 
> Mais globalement le cours est très bien fait !
{: .prompt-tip }