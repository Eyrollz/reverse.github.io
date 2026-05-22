---
title: Partie 13 - 🏆 Challenge - exploiter un binaire avec ret2libc et canaris
date: 2026-04-26 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# 🏆 Challenge : exploiter un binaire avec *ret2libc* et canaris

A ce stade, nous avons vu ensemble pas mal de **protections** et de **méthodes d'exploitation** concernant les *buffer overflow* sur la pile. Ce serait dommage d'oublier les principales informations retenues **faute de pratique**.

Le **but de ce challenge**, en termes de pédagogie, est de consolider vos acquis sur ce qui a été vu jusqu'à présent mais aussi de mieux vous familiariser avec **pwntools**. Également, le code source de ce challenge ne sera pas disponible, il va falloir entamer une première étape de **rétro-ingénierie** afin de comprendre ce qu'il fait et où réside la ou les **vulnérabilités**.

- ⬇️ **Téléchargement** : [chall-ret2libc-canaris.zip](https://drive.proton.me/urls/2X5EGQCE6R#ZbYpyNNZZIZC)
- 🔎 **SHA256 & Analyse Virus Total** : [0dfecc08800539226b687db4871b0662deb677ef8c8e5113199b34c9c1b8108f](https://www.virustotal.com/gui/file/0dfecc08800539226b687db4871b0662deb677ef8c8e5113199b34c9c1b8108f)
- 🎯 **Objectif** : afficher le contenu de `flag.txt` en devenant `root`

## 💻 Contexte d'exécution

Afin de se placer dans le contexte d'exécution prévu pour ce challenge, il est nécessaire de :

- désactiver l'**ASLR** ;
- exploiter le programme en tant qu'utilisateur `challenger`.

Un **conteneur Docker** est fourni afin que vous puissiez avoir un environnement de travail correct et cohérent avec le challenge indépendamment de votre distribution.

## 💫 Lancer le challenge

Ci-dessous les commandes permettant de lancer le challenge :

1. **construction du conteneur** : `docker build -t chall-ret2libc-canaris .`;
2. **lancement du conteneur et du challenge**  : 

```sh
docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined chall-ret2libc-canaris
```

Le port `1234` est ouvert afin de pouvoir **déboguer à distance** le programme avec `gdbserver` depuis la machine hôte. Vous pouvez résoudre le challenge directement **dans le conteneur** Docker.

## 🤓 Quelques conseils 

Voici quelques pistes de réflexion lorsque l'on est face à un challenge de *pwn* :

- Cherchez les **protections en place** pour déterminer quelles techniques d'exploitation seront utilisables et lesquelles ne le sont pas.
- **Débroussaillez** le code désassemblé afin de savoir ce que représente chaque variable.
- Quelles vulnérabilités sont présentes ? Que permet chacune d'elles ? Est-il possible de **combiner l'exploitation de plusieurs de ces vulnérabilités** pour réussir à exploiter le programme ?
- Quelles sont les principales **étapes intermédiaires** avant de réussir à ouvrir un *shell* ?
- N'hésitez pas à utiliser `recvuntil()` afin d'éviter d'avoir un exploit qui fonctionne une fois sur deux. Cela permet également d'éviter de remplir votre script d'appels à `sleep()`.

> Ces conseils **ne sont pas des vérités absolues**. Ce n'est pas parce que vous avez une **approche différente** qu'elle n'est pas valide ou intéressante. 
{: .prompt-tip }

## 💡 Indices

Voici quelques indices qui devraient vous permettre d'avancer lorsque vous êtes bloqués et que vous ne voyez pas comment aller plus loin.

#### 💡 **Indice n°1**

```
TGUgcHJvZ3JhbW1lIHNlbWJsZSB1dGlsaXNlciB1bmUgc3RydWN0dXJlLiBOZSBzZXJhaXQtY2UgcGFzIHBsdXMgc2ltcGxlIGRlIGxhIHLDqWltcGzDqW1lbnRlciBkYW5zIGxlIGTDqWNvbXBpbGF0ZXVyIGFmaW4gZCd5IHZvaXIgcGx1cyBjbGFpciA/CgpFc3NheWV6IGRlIGNvbXByZW5kcmUgY2UgcXVlIGZhaXQgY2hhY3VuZSBkZXMgNCBhY3Rpb25zIGR1IHByb2dyYW1tZS4=
```

#### 💡 **Indice n°2**

```
UG91cnF1b2kgZGlmZsOpcmVudGVzIGZvbmN0aW9ucyBzb250IHV0aWxpc8OpZXMgcG91ciByw6ljdXDDqXJlciBsJ2VudHLDqWUgZGUgbCd1dGlsaXNhdGV1ciA/IFF1ZWxsZXMgc29udCBsZXVycyBkaWZmw6lyZW5jZXMgPw==
```

#### 💡 **Indice n°3**

```
WSBhLXQtaWwgdW4gc291Y2kgYXZlYyBsYSBib3VjbGUgcXVpIHLDqWN1cMOocmUgbGEgZGVzY3JpcHRpb24gPw==
```

#### 💡 **Indice n°4**

```
TGUgY2hvaXggbsKwMyBwZXJtZXQgZCdhZmZpY2hlciBsZXMgZG9ubsOpZXMgZCd1biB1dGlsaXNhdGV1ci4gRXN0LWlsIHBvc3NpYmxlIGRlIGZhaXJlIGZ1aXRlciBsZSBjYW5hcmkgZW4gdXRpbGlzYW50IGFzdHVjaWV1c2VtZW50IGNlIGNob2l4ID8=
```

#### 💡 **Indice n°5**

```
VW5lIGZvaXMgbGUgY2FuYXJpIHLDqWN1cMOpcsOpLCBpbCBlc3QgcG9zc2libGUgZCdleHBsb2l0ZXIgbGUgcHJvZ3JhbW1lIHZpYSB1biByZXQybGliYy4gRW5jb3JlIGZhdXQtaWwgZm9yY2VyIGxhIGZvbmN0aW9uICJtYWluIiDDoCBmaW5pciBzb24gZXjDqWN1dGlvbiAuLi4KCk/DuSBlc3QtaWwgcG9zc2libGUgZGUgc3RvY2tlciBmYWNpbGVtZW50IGxlcyBhcmd1bWVudHMgZGUgbGEgZm9uY3Rpb24gw6AgYXBwZWxlciA/
```