---
title: Partie 25 - 🏆 Challenge - exploitation avancée par ROP (6/6)
date: 2026-04-14 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# 🏆 Challenge : exploitation avancée par ROP (6/6)

En parcourant ce fameux « réseau social professionnel », nous sommes tombés sur un programme développé par ce que l’on appelle un « vibe codeur ». Il affirme que son outil de cryptage de données (sic) est d’une robustesse à toute épreuve.

Et si on lui démontrait le contraire ?

- 🎯 **Objectif** : réussir à afficher le contenu de `flag.txt`.

## ⤵️ Téléchargement du challenge

L'archive du challenge est disponible ici :

- ⬇️ **Téléchargement** : [pwn-rop-chall.zip](https://drive.proton.me/urls/S2ZM97Z4CR#Wz7zqh7GdVBu)
- 🔎 **SHA256 & Analyse Virus Total** : [d02c1d2522d0189880e26eafc40a09279316e4671b068b6e5b4c296a78edef79](https://www.virustotal.com/gui/file/d02c1d2522d0189880e26eafc40a09279316e4671b068b6e5b4c296a78edef79)

> Si vous avez des difficultés à mettre en place le challenge, n'hésitez pas à jeter un œil à la page annexe concernant la [résolution des challenges](/posts/introduction_au_pwn_partie_30/).
{: .prompt-tip }

## 💻 Contexte d'exécution

Le contexte d'exécution est le suivant :

- activer l'ASLR ;
- atteindre l'objectif **en dehors** d'un **débogueur** ;
- atteindre l'objectif **à distance** via le port `12345` ;
- la version de la **glibc** utilisée n'est pas importante.

## 💫 Lancer le challenge

Ci-dessous les commandes permettant de lancer le challenge :

- **construction du conteneur** : `docker build -t pwn-rop-chall .`;
- **lancement du conteneur et du challenge** :

```sh
docker run --rm \
  -p 12345:12345 \
  -p 1234:1234 \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  pwn-rop-chall
```

Les **ports** accessibles sont les suivants :

- `12345` : port du programme à exploiter à distance ;
- `1234` : port qu'il est possible d'utiliser pour déboguer à distance avec `gdbserver`.

## 🤓 Quelques conseils 

- Le challenge peut être résolu en suivant plusieurs étapes petit à petit ;
- la résolution peut paraître longue mais chaque étape intermédiaire n'est pas très compliquée ;
- ne négligez pas la phase de recherche de vulnérabilités ;
- ne croyez pas tout ce que vous voyez 🤭 ;
- ce n'est pas un challenge destiné à exploiter le tas.

## 💡 Indices

Si vous avez été attentifs lors de ce cours jusqu'à présent, vous devriez disposer de tout le bagage théorique pour parvenir à exploiter le programme 😎. Désormais, "il n'y a plus qu'à".