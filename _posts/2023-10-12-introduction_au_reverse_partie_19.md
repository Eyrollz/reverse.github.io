---
title: Partie 19 - L'analyse dynamique - le débogueur (1/4)
date: 2023-10-12 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# L'analyse dynamique - le débogueur (1/4)

Jusqu'à présent, pour faire le *reverse* de programmes, nous nous sommes limités à l'analyse des **instructions** désassemblées et du **code décompilé**. D'ailleurs, j'espère que l'utilisation du décompilateur ne vous a pas fait oublier vos notions d'assembleur car nous allons en avoir grand besoin 😅 !

Le **débogueur** (ou *debugger* 🇬🇧) est un **outil** qui permet de **contrôler** et **gérer** l'exécution d'un programme.

L'utilisation d'un débogueur nous permet notamment de :

- Exécuter un programme **pas à pas**
- Analyser le contenu des **registres** à chaque instruction
- Mettre des **points d'arrêt**
- Modifier le **cours d'exécution** d'un processus en modifiant à la main la valeur de certains registres (dont `eip`/`rip`)
- Inspecter la **mémoire**
- Observer les ***threads*** et **processus**

## gdb : le débogueur GNU

![](/assets/images/introduction_au_reverse/gdb_GNU.png)

Afin de faire de l'analyse dynamique, il va falloir que l'on se dote d'un **débogueur**. Je vous propose d'utiliser **gdb** qui est l'un de *debuggers* les plus utilisés sous Linux.

GDB dispose notamment d'un **grand avantage** et d'un **grand inconvénient** :

- ✅ **Avantage** : Il peut s'utiliser en ligne de commande
- ❌ **Inconvénient** : Il s'utilise en ligne de commande 

En réalité, le fait de pouvoir l'utiliser en ligne de commande permet **plus de flexibilité** : plus rapide à lancer, utilisation dans un conteneur docker, modification des paramètres lors du lancement ...

En revanche, cela implique certaines limitations : pas possible d'utiliser des raccourcis clavier pour réaliser certaines tâches répétitives, pas d'onglets ergonomiques d'affichage de la mémoire ...

> Vous constaterez qu'à fur et à mesure d'utiliser différents outils, on finit par tirer avantage de leurs atouts et on tente de faire abstraction des principaux défauts. L'idée étant de chercher la bonne **synergie** et **complémentarité** entre les outils.
> 
> La preuve : on découvre souvent, après avoir appris à utiliser gdb en CLI que [quelques projets](https://github.com/epasveer/seer) GUI existent, mais finalement on ne les utilise par car on est **plus efficaces** en ligne de commande et on ne voit plus d'intérêt à l'utiliser en mode GUI.
{: .prompt-tip }


## Comment fonctionne un débogueur ?

Le débogueur offre un **cadre d'exécution** au programme débogué. De cette manière, il va pouvoir accéder à pas mal d'informations concernant l'exécution du processus :

![](/assets/images/introduction_au_reverse/info_gdb_access.png)

Si on devait faire une analogie avec le monde réelle, ce serait l'équivalent d'une **électrocardiographie** où plusieurs capteurs nous permettent de récupérer en temps réel plusieurs informations sur le fonctionnement et l'état du cœur d'un patient :

![](/assets/images/introduction_au_reverse/electrocardiographie.png)
De manière sous-jacente, gdb utilise principalement la **fonction** `ptrace` pour récupérer les informations d'un processus débogué. En réalité, `ptrace` est un *wrapper* du *syscall* du même nom, vous vous rappelez, ces fonctions sensibles qui sont exécutées en *kernel land*.

Comme on ne souhaite pas que le débogueur manipule à sa guise un processus, ce qui serait beaucoup **trop risqué**, il passe par `ptrace` afin que l'OS lui permette d'interagir avec le processus analysé. D'ailleurs, il n'est pas très compliqué de développer un débogueur une fois que l'on a compris tout ce que `ptrace` permet de faire.

> Si vous souhaitez avoir un aperçu de ce que propose `ptrace` comme fonctionnalités, vous pouvez simplement consulter son manuel avec `man ptrace`.
{: .prompt-tip }
