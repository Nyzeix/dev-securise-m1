# Modules · Sommaire

Tu fais les modules dans l'ordre. Chaque module continue le précédent, sur la même application.

| | Module | Markdown | PDF |
|---|---|---|---|
| M1 | Cadrer avant de coder | [module.md](M1/module.md) | [Module-1-M1.pdf](../pdf/Module-1-M1.pdf) |
| M2 | Verrouiller l'authentification | [module.md](M2/module.md) | [Module-2-M2.pdf](../pdf/Module-2-M2.pdf) |
| M3 | Décider qui peut quoi | [module.md](M3/module.md) | [Module-3-M3.pdf](../pdf/Module-3-M3.pdf) |
| M4 | Filtrer ce qui entre, échapper ce qui sort | [module.md](M4/module.md) | [Module-4-M4.pdf](../pdf/Module-4-M4.pdf) |
| M5 | Durcir le navigateur et le canal | [module.md](M5/module.md) | [Module-5-M5.pdf](../pdf/Module-5-M5.pdf) |
| M6 | Sortir les secrets du code | [module.md](M6/module.md) | [Module-6-M6.pdf](../pdf/Module-6-M6.pdf) |
| M7 | Auditer, prouver, rendre | [module.md](M7/module.md) | [Module-7-M7.pdf](../pdf/Module-7-M7.pdf) |

## Format de chaque concept

```
1. Rappel concept (cinq à dix lignes)
2. Risque concret
3. Exemple de faille
4. Action à faire dans ton application
5. Test de validation
6. Trace dans le rapport
```

## Tagger ta progression

À la fin de chaque module, pose un tag Git :

```bash
git tag M1-cadrage
git tag M2-auth-securise
git tag M3-rbac-securise
git tag M4-injections-corrigees
git tag M5-headers-csrf
git tag M6-secrets-logs
git tag M7-audit-final
```
