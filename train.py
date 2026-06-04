from lib.model import train_model

DATA_FILE = "data/sample_data/Honeynet botnet attack timestamp 32 qubits final copy - Sheet1.csv"


def main():
    training = train_model(DATA_FILE)

    print(f"Training complete using {training['data_file']}")
    print(f"Rows trained on: {training['rows_trained']}")
    print(f"Rows tested on: {training['rows_tested']}")
    print(f"Saved trained model to {training['model_file']}")
    print(f"Saved engineered training features to {training['features_file']}")
    print()
    print("Validation metrics:")
    print(f"Accuracy: {training['accuracy']:.4f}")
    print(f"Precision: {training['precision']:.4f}")
    print(f"Recall: {training['recall']:.4f}")
    print(f"F1 score: {training['f1']:.4f}")
    print()
    print("Confusion matrix:")
    print(f"Labels: {training['confusion_matrix_labels']}")
    print(training["confusion_matrix"])
    print()
    print("Detailed results:")
    print(training["report"])


if __name__ == "__main__":
    main()
