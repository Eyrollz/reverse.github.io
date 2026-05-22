---
title: Partie 29 - Conclusion
date: 2026-04-10 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Conclusion

Ce cours d'**introduction au pwn** touche à sa fin. J'espère sincèrement que ce cours, que ce soit dans son entièreté ou en partie, aura pu vous être bénéfique et vous prouver que rien n'est difficile à comprendre tant que l'on reste **motivé**, **curieux** et que l'on **poursuit ses efforts**.

> Mais tu n'as pas fini la *timeline* avec toutes les techniques d'exploitation. Il y aura une suite ? 
{: .prompt-tip }

Ptet' bien qu'oui, ptet' bien que non 🙃. En tout cas, cela me ferait plaisir de savoir quel serait le prochain cours que vous aimeriez lire un jour ? N'hésitez pas à me faire un retour par mail 😉.

## 💡 « Science sans conscience n’est que ruine de l’âme »

Il n'existe pas 36 000 manières de gagner sa vie en faisant de la recherche de vulnérabilité. Il existe de nombreux métiers dans ce domaine que l’on pourrait, grosso modo, classer dans l’une de ces catégories :

1. 🟢 recherche de vulnérabilité, **en interne**, au sein d'une entreprise afin de sécuriser les programmes et applications ;
2. 🟢 recherche de vulnérabilité de type **bug bounty** permettant d’être rémunéré pour la découverte de failles afin que les entreprises concernées puissent les corriger ;
3. 🟠 recherche de vulnérabilité sous forme de **prestation de service pour des clients** ;
4. 🔴 **commercialisation d’exploits** via des intermédiaires spécialisés ;
5. 🔴 **cybercriminalité** à but lucratif.

> Tout d'abord, le **code couleur** et les **remarques** ci-dessous sont **subjectifs**. À chacun de se faire son propre avis sur la question.
{: .prompt-tip }

Dans les **deux premiers cas** (1️⃣ et 2️⃣), ce qui est intéressant est que la finalité de la recherche est **la protection des systèmes**. Ainsi, on ne devrait, en théorie, pas faire de tort à qui que ce soit en menant ce type d'activité. Le seul défaut de ces activités, et notamment dans le premier cas, est qu'il est très difficile d'y être recruté en début de carrière.

Pour ce qui est du **troisième cas** 3️⃣ : la recherche de vulnérabilités comme service pour des clients externes. Il s'agit d'une activité très répandue que ce soit en France, en Europe ou ailleurs. Très souvent, les clients finaux sont des **entités étatiques** qui peuvent aussi bien utiliser à **bon escient** les exploits développés (contre-terrorisme, lutte contre la délinquance etc.) qu'à **mauvais escient** (surveillance abusive, participation ou collaboration avec des états g3n0cid4ir3s etc.). C'est généralement une activité plutôt accessible en début de carrière.

Dans le **quatrième cas** 4️⃣, il s'agit de la vente d'exploits à des intermédiaires qui les revendent ensuite comme bon leur semble. Contrairement au précédent cas, vous ne savez jamais qui achètera *in fine* l'exploit et si ce client est connu pour en faire bon usage ou non. Cela peut être à la fois utilisé par un État pour traquer des criminels tout comme cela peut être utilisé par un État en vue de faciliter la mise en place d'un g3n0cid3 que ce soit au Moyen-Orient, en Europe ou ailleurs.

> Pour parler français, dans les cas 3️⃣ et 4️⃣, ce type de recherche de vulnérabilités est de la **vente d'armes** (numériques). La principale différence entre les cas 3️⃣ et 4️⃣ est que dans le cas 3️⃣ vous savez généralement pour qui vous travaillez.
> 
> [Voici un exemple ](https://www.youtube.com/watch?v=zRSv0Cs4tXY&list=PLiEHUFG7koLsv_QQnYtKRV9PPR8_kmpF_) des conséquences de l'utilisation d'exploits par des entreprises principalement liées, de près ou de loin, à des entités g3n0cid4ir3s.
{: .prompt-tip }

Enfin, le **cinquième cas** 5️⃣ est généralement le chemin emprunté par ceux dont le but visé est de gagner de l'argent via de la recherche et l'exploitation de vulnérabilités et ce, peu importe le moyen utilisé. Vous imaginez bien que cela est d'une part illégal mais surtout que cela a des conséquences énormes sur les cibles.

Pour résumer, indépendamment du travail effectué, nous devrions toujours nous poser la question suivante : **est-ce que ce que je produis chaque jour via mes efforts et mon travail contribue à rendre le monde meilleur ?**

## ↗️ Aller plus loin

Ce cours aborde majoritairement des aspects **théoriques**, même si plusieurs exercices et challenges ont permis de mettre ces notions en pratique. Cela dit, rien ne remplace une **pratique régulière** : que ce soit à travers d’autres challenges ou l’analyse de programmes réels, **c’est l’entraînement qui permet de réellement consolider les acquis**.

Pour rappel, plusieurs plateformes proposant des challenges de _pwn_ ont été présentées dans le [chapitre d'introduction au pwn](/posts/introduction_au_pwn_partie_1/). Chacune possède ses spécificités : à vous de choisir celles qui correspondent le mieux à vos objectifs et à votre manière d’apprendre.

N’hésitez pas à revenir sur certains chapitres si des notions vous échappent. Cela arrive très fréquemment en *pwn* 😆. Quelques mois sans pratiquer suffisent parfois à donner l’impression d’avoir tout oublié lorsque l’on s’y remet.

![](/assets/images/introduction_au_pwn/8gh1d9.gif)

Enfin, les qualités essentielles pour progresser durablement sont la **curiosité** et la **persévérance**. Avec de l’autonomie, de la méthode et du temps, il est possible de comprendre n’importe quelle notion. Il ne faut jamais considérer une difficulté comme insurmontable, ni penser que certaines compétences sont réservées à une quelconque "élite".

## Avant de se quitter

Tout d'abord, merci d'avoir pris le temps de lire ce cours. Il s'agit de la **première édition** de ce cours, qui n’est évidemment pas parfaite et contient sûrement des erreurs tant sur le fond que sur la forme. Je ne prétends évidemment pas avoir la science infuse 😅. Ainsi, si vous pensez qu'un changement s'impose sur l'un de ces deux aspects, n'hésitez pas à **nous contacter** (par mail ou autre) pour en discuter.

De même, si vous ne comprenez toujours pas une notion présentée à travers ces différents chapitres, cela signifie sûrement que l'on n'a pas su la présenter et l'expliquer de la meilleure manière et qu'un changement ou une amélioration s'impose.

De manière générale, nous sommes ouverts à la discussion et nous essayons d'être réactifs afin de répondre aux questions dans un délai raisonnable.

Sur ce, prenez soin de vous et à la prochaine !

Dieu sait mieux.