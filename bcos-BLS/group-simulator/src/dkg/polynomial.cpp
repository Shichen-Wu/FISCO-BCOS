#include "dkg/polynomial.h"

Polynomial::Polynomial(uint32_t threshold, const FrNative& master_sk) {
    uint32_t degree = threshold - 1;
    coeffs_.resize(degree + 1);
    if (BlsWrapper::frIsZero(master_sk)) {
        coeffs_[0] = BlsWrapper::generateSecretKey();
    } else {
        coeffs_[0] = master_sk;
    }
    for (size_t i = 1; i < coeffs_.size(); ++i) {
        coeffs_[i] = BlsWrapper::generateSecretKey();
    }
}

Polynomial::Polynomial(const std::vector<FrNative>& coeffs)
    : coeffs_(coeffs) {}

FrNative Polynomial::evaluate(uint32_t x) const {
    return BlsWrapper::evaluatePolynomial(coeffs_, x);
}

FrNative Polynomial::getSecret() const {
    return coeffs_[0];
}
