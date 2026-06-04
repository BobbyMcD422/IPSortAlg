from lib.model import predict_file

DATA_FILE = "data/sample_data/Honeynet botnet attack timestamp 32 qubits final copy - Sheet1.csv"


def main():
    prediction = predict_file(DATA_FILE)

    print(f"Predicted labels for {prediction['data_file']}")
    print(f"Rows predicted: {prediction['rows_predicted']}")
    print(f"Loaded model from {prediction['model_file']}")
    print(f"Saved filled sheet to {prediction['output_file']}")
    print()
    print("Example predictions:")
    print(
        prediction["results"][
            ["time", "IP", prediction["target_column"], "prediction_confidence"]
        ].head(10)
    )


if __name__ == "__main__":
    main()
