import predict
import review_blacklist


def main():
    print("Applying rules to sample data...")
    print()
    predict.main()
    print()
    print("Reviewing blacklist candidates...")
    review_blacklist.main()


if __name__ == "__main__":
    main()
