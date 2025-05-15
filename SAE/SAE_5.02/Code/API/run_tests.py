import unittest
import sys
import time
from colorama import init, Fore, Style
from test_api import TodoListAPITests
from test_api_security import APISecurityTests
import logging
import coverage

# Initialize colorama
init()

def run_test_suite():
    # Configuration du logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Démarrer la couverture de code
    cov = coverage.Coverage()
    cov.start()

    # Créer une suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Ajouter les tests fonctionnels
    print(f"{Fore.CYAN}=== Démarrage des tests fonctionnels ==={Style.RESET_ALL}")
    functional_tests = loader.loadTestsFromTestCase(TodoListAPITests)
    suite.addTest(functional_tests)

    # Ajouter les tests de sécurité
    print(f"{Fore.CYAN}=== Démarrage des tests de sécurité ==={Style.RESET_ALL}")
    security_tests = loader.loadTestsFromTestCase(APISecurityTests)
    suite.addTest(security_tests)

    # Créer un runner personnalisé
    class CustomTestResult(unittest.TextTestRunner().run(suite).__class__):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.successes = []

        def addSuccess(self, test):
            self.successes.append(test)
            super().addSuccess(test)

    # Exécuter les tests
    start_time = time.time()
    runner = unittest.TextTestRunner(
        verbosity=2,
        resultclass=CustomTestResult,
        stream=sys.stdout
    )
    
    result = runner.run(suite)

    # Arrêter la couverture de code
    cov.stop()
    cov.save()

    # Afficher le résumé
    duration = time.time() - start_time
    total_tests = result.testsRun
    passed_tests = len(result.successes)
    failed_tests = len(result.failures)
    error_tests = len(result.errors)
    skipped_tests = len(result.skipped) if hasattr(result, 'skipped') else 0

    print("\n" + "="*70)
    print(f"{Fore.CYAN}Résumé des tests:{Style.RESET_ALL}")
    print(f"Durée totale: {duration:.2f} secondes")
    print(f"Tests exécutés: {total_tests}")
    print(f"{Fore.GREEN}Tests réussis: {passed_tests}{Style.RESET_ALL}")
    if failed_tests > 0:
        print(f"{Fore.RED}Tests échoués: {failed_tests}{Style.RESET_ALL}")
    if error_tests > 0:
        print(f"{Fore.RED}Erreurs: {error_tests}{Style.RESET_ALL}")
    if skipped_tests > 0:
        print(f"{Fore.YELLOW}Tests ignorés: {skipped_tests}{Style.RESET_ALL}")
    
    success_rate = (passed_tests / total_tests) * 100
    print(f"Taux de réussite: {success_rate:.1f}%")

    # Générer le rapport de couverture
    print(f"\n{Fore.CYAN}Rapport de couverture de code:{Style.RESET_ALL}")
    cov.report()
    
    # Générer un rapport HTML détaillé
    cov.html_report(directory='coverage_report')
    print(f"\nRapport de couverture HTML généré dans le dossier 'coverage_report'")
    
    print("="*70)

    # Retourner un code d'erreur si des tests ont échoué
    if failed_tests > 0 or error_tests > 0:
        return 1
    return 0

if __name__ == '__main__':
    try:
        print(f"{Fore.CYAN}Démarrage des tests...{Style.RESET_ALL}")
        exit_code = run_test_suite()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tests interrompus par l'utilisateur{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Erreur lors de l'exécution des tests: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
