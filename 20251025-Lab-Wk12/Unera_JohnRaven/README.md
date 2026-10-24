# Laboratory Activity #06: CRISP-DM | Testing

**Unera, John Raven S.** · CIT 401A - IT31S1 - Fundamentals of Business Analytics · Mr. Richard Kho

| File | Lab item |
|---|---|
| `lab06_wk12_dump.sql` | III-2: MySQL DB table dump (database `lab06_wk12`, tables `cyber_attacks_raw` and `cyber_attacks_prepared`, 40,000 rows each) |
| `01_import_and_prepare.sql` | III-1: Script used to import the CSV and build the prepared table |
| `J48graft_C3_best.model` | IV-2: Model with the highest measurement (J48graft, 10-fold CV accuracy 33.7375%, Kappa 0.0056) |
| `C3_prepared_infogain_top8.arff` | Final prepared dataset used to build the model (8 attributes + class `action_taken`) |

Restore the database: `mysql -u root -p < lab06_wk12_dump.sql`
