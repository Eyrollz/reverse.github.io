---
layout: page
title: Home
order: 1
---

{% if site.active_lang == "fr" %}
# Bienvenue !

L'objectif de ce site est le partage de connaissances autour du **reverse** (alias rétro-ingénierie 🇫🇷).

Le *reverse* est utilisé dans de nombreux domaines :

- Analyse de *malwares*
- Recherche et exploitation de vulnérabilités
- *Modding*
- Émulation
- Débogage bas niveau
- Analyse *forensic*

Malheureusement, le reverse peut également être utilisé pour **cracker** des programmes (jeux ou licences ...). Bien que démarrer avec de petits *crackmes* puisse être intéressant pour débuter dans le reverse, il faut savoir que le cracking de programmes propriétaires est **illégal**.

> En **aucun cas** le contenu proposé sur ce site n'est destiné à être utilisé à des fins **illégales**, **immorales** ou **non éthiques** 😶.
{: .prompt-danger }

Si tu es intéressé par le fait de **partager du contenu** sur la plateforme, n'hésite pas à nous contacter 😜 !

Sur ce, bonne lecture 📖 !

## ✅ Cours disponibles

- [Introduction au pwn](/categories/introduction-au-pwn/) (30 chapitres)
- [Exploitation de la heap](/categories/exploitation-de-la-heap/) (24 chapitres)
- [Introduction au reverse](/categories/introduction-au-reverse/) (25 chapitres)
- [Introduction à l'exécution symbolique avec angr](/categories/introduction-%C3%A0-l-ex%C3%A9cution-symbolique-avec-angr/) (5 chapitres)

## ⚒️ Cours à venir

- L'analyse d'applications Android 
- L'analyse de *malwares*


{% elsif site.active_lang == "en" %}
# Welcome!

The goal of this site is to share knowledge about **reverse engineering**.

*Reverse engineering* is used in many areas:

- *Malware* analysis
- Vulnerability research and exploitation
- *Modding*
- Emulation
- Low-level debugging
- *Forensic* analysis

Unfortunately, reverse engineering can also be used to **crack** programs (games, licenses ...). Although starting with small *crackmes* can be interesting when getting into reverse engineering, you should know that cracking proprietary programs is **illegal**.

> Under **no circumstances** is the content provided on this site intended to be used for **illegal**, **immoral**, or **unethical** purposes 😶.
{: .prompt-danger }

If you are interested in **sharing content** on the platform, feel free to contact us 😜!

With that, happy reading 📖!

## ✅ Available courses

- [Introduction to symbolic execution with angr](/en/categories/introduction-to-symbolic-execution-with-angr/) (5 chapters)

## 🇫🇷 ➡️ 🇬🇧 Upcoming translations

- [Introduction to pwn](/categories/introduction-au-pwn/) (30 chapters) 
- [Heap exploitation](/categories/exploitation-de-la-heap/) (24 chapters)
- [Introduction to reverse engineering](/categories/introduction-au-reverse/) (25 chapters)

## ⚒️ Upcoming courses

- Android application analysis 
- *Malware* analysis
{% endif %}