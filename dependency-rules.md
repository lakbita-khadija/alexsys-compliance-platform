# Dependency Rules

## 1. Règle

`infrastructure/` (`collectors/`) peut dépendre de `domain/`. `domain/` ne
dépend jamais d'`infrastructure/` ni d'aucun SDK cloud/framework web/ORM.

## 2. Vérification (CURRENT CODE, grep exhaustif au moment de la rédaction)

```
$ grep -rhn "^from |^import " scanner --include="*.py" | grep -v "^scanner"
```

Dépendances externes non-stdlib trouvées : **`pydantic`** (import
`BaseModel`, `ConfigDict`, `Field`, `field_validator` — utilisé dans
`schema.py`, `value_objects.py`, `rule_engine.py`), **`yaml`** (utilisé
uniquement dans `rule_engine.py`, exclusivement via `yaml.safe_load` —
jamais `yaml.load` non sécurisé).

Tout le reste : stdlib (`dataclasses`, `enum`, `typing`, `abc`, `pathlib`,
`datetime`, `collections`, `logging`, `uuid`) ou imports internes
(`scanner.*`).

**Aucun `boto3` importé directement** — vérifié séparément :
`grep -rln "^import boto3\|^from boto3" scanner/` → aucun résultat, y
compris dans `collectors/aws_collector.py` (session injectée en paramètre).

## 3. Violations détectées

**Aucune.** La règle de dépendance Domain → aucune infrastructure est
respectée dans les faits, avant même qu'un outil comme `import-linter` ne
la vérifie mécaniquement (NOT IMPLEMENTED — voir `13-decisions/`).

## 4. Ce que ça signifie architecturalement

La restructuration future en dossiers `domain/`/`application/`/
`infrastructure/`/`adapters/` (documentée dans les sessions antérieures de
ce projet comme "Phase 2") formaliserait une propriété qui existe déjà
dans le code, elle ne la créerait pas. C'est un point factuel vérifiable,
pas une opinion.
