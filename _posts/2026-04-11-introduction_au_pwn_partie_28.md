---
title: Partie 28 - Méthodologie - comment identifier et analyser des vulnérabilités
date: 2026-04-11 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Méthodologie : comment identifier et analyser des vulnérabilités

Vous l'avez sans doute remarqué : ce cours met davantage l'accent sur la partie **exploitation** que sur la partie **recherche de vulnérabilités**. En effet, l'exploitation requiert tout de même pas mal de **compétences** et de **connaissances**. Sauf qu'il ne faut pas oublier :

![](/assets/images/introduction_au_pwn/meme_vuln_exploit.png)

Nous allons donc, au cours de ce chapitre, nous intéresser à **quelques méthodes** de recherche de vulnérabilités. Le traiter en un seul chapitre est évidemment trop court pour être exhaustif et applicable à toutes les applications imaginables. Mais, au moins, cela permettra de comprendre **l'état d'esprit à avoir** dans de la recherche de vulnérabilité.

Pour cela, nous allons distinguer **deux types de programmes** à exploiter :

- **les challenges** : on sait qu'il y a une ou plusieurs vulnérabilités. Il suffit de les trouver et savoir les exploiter correctement ;
- **les autres** : on ne sait pas par où commencer ni s'il y a réellement une vulnérabilité dans le programme.

## 🏋️‍♂️ Les challenges

Bien que la méthodologie de la résolution des challenges n'entre pas totalement dans un **contexte d'exploitation réel**. Il n'en demeure pas moins que cela reste l'une des meilleures manières de progresser. Le seul défaut est que dans certains cas, nous savons très bien de quel type est la vulnérabilité à exploiter ou, au moins, nous savons où commencer à chercher.

Tout d'abord, si le challenge contient un énoncé voire un indice dans le titre, il convient de prendre un peu de temps pour comprendre ce qu'il implique. Par exemple, s'il s'agit plutôt d'un challenge d'exploitation dans le tas, il y a de grandes chances que le challenge soit compilé avec des versions spécifiques, souvent anciennes, de la **libc**. Idem s'il y a de nombreux appels à `malloc`, `free` etc. 

L'une des premières choses à faire avec un programme est de lancer `checksec` afin de **déterminer les protections** qui y sont présentes.

> `checksec` peut parfois donner des **faux positifs** 😵‍💫 notamment en ce qui concerne les **canaris**, **RELRO** et parfois **RWX**. Ne prenez pas toujours ce qu'il dit pour argent comptant et **vérifiez par vous-mêmes** dans **gdb** et dans le code décompilé si ce qu'il raconte est correct.
{: .prompt-warning }

Très souvent, l'absence d'une protection n'est pas anodine :

- s'il n'y a pas de **canari**, il est peut-être possible de déclencher un *buffer overflow* sur la **pile** ;
- s'il n'y a pas de **RELRO** ou que celle-ci est **partielle**, il pourrait être judicieux de **corrompre l'une de ses entrées** pour basculer vers une exécution de code autre part ;
- lorsque la **pile** ou que le **tas** est **exécutable**, on peut envisager **l'utilisation d'un shellcode**. Si aucune de ces deux zones n'est RWX, n'hésitez pas à chercher d'autres zones mémoire via **gdb** qui le seraient potentiellement.

> Il ne faut pas non plus que ce type d’outils **restreigne excessivement notre vision**. La présence de canaris n’implique pas qu’un dépassement de mémoire sur la pile soit impossible. De la même manière, l’absence de zones **RWX** ne signifie pas nécessairement qu’un **shellcode** est inexploitable, notamment lorsqu’un appel à `mprotect` est envisageable.
> 
> En définitive, ces outils et les informations qu’ils fournissent ne doivent pas **brider notre capacité d’analyse** ni nous dissuader d’explorer des vulnérabilités que l’on suppose, à tort, inexistantes.
{: .prompt-tip }

## 💿 Les autres types de programmes

Et si on voyait plus grand ? Bah oui, les challenges c'est bien, mais généralement ce qui est plus intéressant c'est de trouver des vulnérabilités dans des programmes **réellement utilisés**.

Pour cela nous allons principalement nous focaliser sur les programmes codés en C et qui tournent sous Linux. Certaines méthodes et astuces que nous verrons pourrons bien sûr être utilisées dans d'autres contextes comme des programmes C sous Mac OS, Windows etc.

### 🔦 Evaluer la surface d'attaque

Tout d'abord, avant même de commencer à chercher des vulnérabilités, il faut absolument savoir de quoi la surface d'attaque est constituée. La **surface d’attaque** désigne l’ensemble des **points d’entrée**, **fonctionnalités**, **interfaces** et **comportements** exploitables par lesquels un attaquant peut interagir avec un système.

> En quoi est-ce si important que cela ?
{: .prompt-info }

Voici un exemple assez simple pour comprendre en quoi cette étape est primordiale : on passe pas mal de temps à analyser le programme et on trouve enfin une vulnérabilité (ex : *buffer overflow*) dans une fonction `sub_xxxxxxx` qui sera très simple à exploiter. 

Sauf que le souci est que `sub_xxxxxxx` n'est jamais atteinte par le programme :

- parce que c'est du **code mort** ;
- parce qu'elle n'est accessible qu'en étant **administrateur** ;
- parce qu'elle n'est accessible que lorsque le **mode de débogage est activé**.

Ainsi, l’évaluation de la surface d’attaque permet de prioriser efficacement les zones du code réellement accessibles et de concentrer nos efforts là où une interaction est possible. 

À l’inverse, cette analyse ne doit pas restreindre excessivement la recherche : des fonctionnalités *a priori* inaccessibles peuvent devenir pertinentes si un contournement de contrôle ou une élévation de privilèges est découverte. Par exemple, des fonctions **réservées aux administrateurs** méritent parfois d'être identifiées, car elles peuvent devenir exploitables dès lors qu’un moyen d’obtenir ces privilèges est trouvé.

> Et on fait comment pour la trouver cette surface d'attaque ?
{: .prompt-info }

Il faut tout d'abord déterminer tout ce qui constitue l'entrée utilisateur (ou *input*). En d'autres termes : comment puis-je interagir avec cette application ?

Voici quelques exemples :

- `stdin` : le programme lit l'entrée utilisateur depuis l'entrée standard et la traite ;
- une *socket* **réseau** : le programme est en attente de connexions extérieures et traite la requête une fois reçue ;
- **lecture depuis un fichier accessible** : le programme lit des données depuis un fichier dont le contenu peut être modifié par l'utilisateur ;
- les **arguments de la ligne de commande** (`argv`) passés au lancement du programme ;
- les **variables d’environnement** (`envp`), souvent utilisées pour configurer le comportement du programme ;
- les **signaux** reçus par le processus (`SIGALRM`, `SIGUSR1`, etc.), qui peuvent déclencher des chemins d’exécution spécifiques ;    
- les **données partagées** via des mécanismes IPC (mémoire partagée, pipes nommés, messages en fil d'attente ...).

### 🔬 Analyser comment sont traitées les données

Une fois que l'on a une idée de la surface d'attaque, il est désormais temps de s'intéresser à **ce que le programme fait concrètement des entrées utilisateur**. C'est à partir de cette étape que le travail de *reverse* prend toute son importance.

En fait, peu importe les données que lit le programme, il y a toujours un certain nombre de questions à se poser :

- Comment les données sont-elles traitées ? 
- Par quelles fonctions les données passent-elles ?
- Est-ce que la modification de la taille ou du contenu des données peut avoir un effet sur le fonctionnement du programme ?
- Y a-t-il des conversions ? Sérialisation ? Utilisation de données sous forme de structure [type-longueur-valeur](https://fr.wikipedia.org/wiki/Type-length-value) ?
- Lorsque l’entrée utilisateur doit respecter un format spécifique (ex : XML, HTTP, fichier chiffré, certificat, etc.), que se passe‑t‑il si ce format est partiellement ou volontairement corrompu ?

### L'analyse "bas niveau"

Afin de répondre à ces questions lors de l'analyse du programme, nous allons descendre d'un cran et nous poser des questions supplémentaires plus "bas niveau" :

- Si la fonction utilise un *buffer*, **comment ce dernier est-il généré** ? A-t-il une **taille suffisante** pour l’usage qu’en fait le programme ? 
- Si des **comparaisons** sont réalisées, est-ce que le **signe de la comparaison** (`signed` / `unsigned`) est **cohérent avec le signe** des variables comparées ?
- Jeter un œil aux **types** et notamment **la taille des variables utilisées** :
	- Que se passe-t-il si l'on tente d'écrire `0xdeadbeef` dans une variable de type `__int16` de deux octets ? 
	- Que se passe-t-il lorsque j'ajoute `1` à une variable de type `int` ayant pour valeur `0xffffffff` ?
	- Même question si on tente de stocker `0xdeadbeef * 0x10` dans une variable de type `int`.
- Quels sont les arguments qui doivent être donnés à une fonction et quelle est sa valeur de retour ?
	- La fonction admet-elle des **comportements indéfinis** lorsque certaines valeurs sont transmises ? 
	- De manière générale, utiliser le `man` d'une fonction permet d'avoir une idée des **erreurs d'utilisation ou d'implémentation** de la fonction.
- S'il y a une lecture et écriture dans un fichier, est-ce qu'une [situation de compétition](https://fr.wikipedia.org/wiki/Situation_de_comp%C3%A9tition) est possible ?

Encore une fois, la liste n'est pas exhaustive et ne doit pas être utilisée comme une simple liste de cases à cocher. Elle peut **servir de support** dans le cas où l'on a bien avancé dans la rétro-ingénierie et que l'on pense que l'on a pas assez passé de temps dans telle ou telle partie du programme.

En fait, ces questions doivent être adressées à tout moment, au fur et à mesure que l'on avance dans l'analyse.

### L'analyse "haut niveau"

Une fois les parties accessibles du programme analysées, les structures internes *reversées* et les vulnérabilités potentielles identifiées, il est temps de **prendre du recul** et d’observer le **fonctionnement global** de l’application afin d’y déceler d’éventuelles failles.

Par « analyse haut niveau », on entend l’étude de la **logique générale** du programme. Cette étape ne conduit généralement pas à des corruptions mémoire directes, mais elle est souvent déterminante pour identifier des **bugs de logique**, parfois tout aussi critiques. Ces derniers peuvent en effet permettre des contournements de mécanismes de sécurité, des élévations de privilèges ou des accès non autorisés.

Les points à examiner à ce stade dépendent naturellement du type d’application et de sa logique interne 😅. C’est précisément le moment d’adopter un état d’esprit "[think out of the box](https://fr.wikipedia.org/wiki/Thinking_outside_the_box)" : l’objectif n’est plus d’analyser une fonction isolée, mais de repérer des incohérences ou des failles dans le **processus global de fonctionnement** de l’application.

### Faire un bilan des vulnérabilités trouvées

Il arrive souvent que dans des programmes, une vulnérabilité trouvée ne soit pas suffisante pour l'exploiter. Auquel cas il sera nécessaire de faire un bilan des bugs ou vulnérabilités trouvés afin de déterminer ce qu'il sera possible d'en faire et les résultats que l'on peut obtenir en **combinant plusieurs vulnérabilités**.

## 📋 Synthèse

Au final, la recherche de vulnérabilités repose sur **trois piliers essentiels** :

- utiliser des **astuces** et des **raccourcis** afin d’orienter efficacement l’analyse ;
- adopter une **méthodologie rigoureuse**, sans foncer tête baissée ;
- éviter de se limiter à un **ensemble restreint** de types de vulnérabilités, au risque de passer à côté d’autres failles tout aussi exploitables.

Ce chapitre n’a évidemment pas vocation à être exhaustif. La méthodologie de recherche dépend fortement du **type de programme analysé** et de son **contexte d’exécution** : on n’aborde pas de la même manière un programme Java, une application C en *userland* ou un module *kernel* Linux.

Enfin, ce chapitre n’aborde pas l’usage des outils dédiés à la recherche de vulnérabilités, ni l’importance de prendre le temps d’en découvrir de nouveaux afin de **gagner en efficacité** et en **profondeur d’analyse**.