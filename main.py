"""Run prediction and blacklist review as one console workflow."""

import predict
import review_blacklist


def main():
    """Apply rules to sample data, then review blacklist candidates."""
    print("Applying rules to sample data...")
    print()
    predict.main()
    print()
    print("Reviewing blacklist candidates...")
    review_blacklist.main()


if __name__ == "__main__":
    main()
