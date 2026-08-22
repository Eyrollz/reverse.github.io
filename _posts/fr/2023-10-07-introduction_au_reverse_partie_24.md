---
title: Partie 24 - Conclusion
date: 2023-10-07 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Conclusion

Nous voilà à la fin de ce cours **d'introduction au *reverse*** !

![](/assets/images/introduction_au_reverse/ash.png)

Nous avons appris énormément de choses ensemble au cours des différents chapitres. Nous nous sommes attelés à voir les **notions primordiales** et ce qui en découle afin de ne pas faire non plus un cours de 100 pages 🤕.

Néanmoins, je tiens à la rappeler encore une fois, il ne s'agit que d'un modeste cours d'introduction et énormément de choses n'ont **pas été vues**. Nous pouvons notamment citer :

- le *reverse* sous **Windows**, Mac OS, Android, iOS ...
- le *reverse* sur de l'**embarqué**, **IoT** ...
- les principales méthodes d'**obfuscation** et leurs **contremesures**, même si nous en avons vues quelques unes
- les détails des autres **langages assembleur** : ARM, MIPS, RISC-V ...
- la **recherche et exploitation de vulnérabilité**
- l'**exécution symbolique** : comment émuler un programme avec des variables symboliques afin de couvrir plus de code et trouver les valeurs en entrée permettant d'y arriver (mais un cours est dispo ici : [introduction à l'exécution symbolique](https://reverse.zip/categories/introduction-%C3%A0-l-ex%C3%A9cution-symbolique-avec-angr/))
- la **décompilation** des programmes développés dans **d'autres langages** comme : le C++ (ressemble en partie au C), Golang, Rust ...
- l'utilisation **avancée** d'IDA avec des **scripts** (version Pro seulement), de Ghidra ou de Binary Ninja
- et bien d'autres !

## Aller plus loin

> Y a encore tellement de choses à apprendre, par où commencer et où trouver des ressources 🤯 ?
{: .prompt-info }

Il y a **plusieurs méthodes** pour apprendre à avancer en *reverse*. 

Lorsque l'on début, il peut être très intéressant d'enchaîner les challenges / *crackmes* en essayant de bien comprendre à chaque fois ce qu'il se passe et comment le résoudre.

Pour cela, voici quelques sites pour pouvoir avancer :

- 🇫🇷 [Root Me](https://www.root-me.org/) : comment parler de challenges si on ne parle pas de Root Me ? Il y a sur ce site, francophone de base, énormément de catégories dont une catégorie **Cracking** et **App Système** pour bien se rôder en *reverse*. Les challenges sont globalement triés par complexité. Autant les premiers peuvent se faire assez rapidement, autant pour les derniers, va falloir être solide sur ses appuis 😵‍💫 ! De plus, il y a un serveur Discord ou vous pourrez discuter avec d'autres passionnés et même y demander de l'aide. Peut être que l'on s'y retrouvera d'ailleurs ! Personnellement c'est là où j'ai quasiment tout appris, ainsi je leur suis redevable, ne serait-ce qu'en vous recommandant cette incroyable plateforme !
- 🇫🇷 [Hackropole](https://hackropole.fr/fr/) : il s'agit d'une plateforme française assez récente développée par l'ANSSI et qui contient ses nombreux challenges qu'ils publient lors du challenge du [FCSC](https://cyber.gouv.fr/france-cybersecurity-challenge-2023). Là, pareil, il y a beaucoup de catégories dont une catégorie *reverse*. Les challenges peuvent parfois sembler plus simples ou bien plus compliqués que ceux de Root Me. Ce qui est sûr c'est que ce sont très souvent des challenges de qualité !
- 🇬🇧 [crackmes.one](https://crackmes.one/) :  une autre plateforme avec plusieurs *crackmes*. Le site est un peu plus brouillon que les précédents mais ce qui est pas mal est que l'on peut y trouver des challenges dans des langages assembleurs autre que x86 (comme sur Hackropole d'ailleurs).

> S'il vous arrive de stagner parfois, de galérer sur un challenge pas mal de temps ou de ne pas comprendre certaines choses, sachez que cela est tout à fait normal et que cela fait partie de l'apprentissage.
> 
> Ce qui va vous permettre de devenir de plus en plus fort en *reverse* est la **persévérance** et la **patience**.  
{: .prompt-tip }

Aussi, nous avons essayé d'avancer ensemble tout au long des différents chapitres lorsque l'on faisait face à une difficulté. Il est désormais temps d'apprendre à lire et comprendre les **documentations** afin de pouvoir se débrouiller face à des situations **complexes**.

Ensuite, une fois que vous êtes assez avancés en termes de *reverse*, vous pourrez vous attaquer à des analyses de *malwares* ou de la recherche de vulnérabilités (à des fins de protection). 

N'hésitez pas non plus à aller jeter un œil aux **autres cours** de *reverse*, cela pourrait vous intéresser 😉 !

## Remerciements

Tout d'abord je tiens à vous remercier d'être restés **jusqu'au bout** malgré mes blagues pas marrantes. J'espère avoir été **pédagogue** afin que tout le monde puisse découvrir le *reverse* sans en être dégoûté de prime abord.

Si vous avez des **commentaires**, des **retours**, des **critiques** (positives ou non 😅), des **pistes d'amélioration**, n'hésitez pas à nous contacter ! Cela permettra d'améliorer continuellement ce cours, ainsi que les autres cours proposés sur ce site.

Je remercie évidemment le Tout Miséricordieux qui nous a facilité la rédaction de cours et nous a permis d'arriver jusqu'au bout en restant motivé, sans quoi, ce cours n'aurait jamais vu le jour.

J'espère que toutes les notions que vous avez apprises lors de ce cours seront utilisées à **bon escient** et de **manière éthique** afin de faire avancer les choses dans le **bon sens**. Âmin.

Dieu sait mieux.