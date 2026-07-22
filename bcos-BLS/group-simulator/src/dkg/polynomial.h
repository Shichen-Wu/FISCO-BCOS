#ifndef GROUP_SIMULATOR_DKG_POLYNOMIAL_H_
#define GROUP_SIMULATOR_DKG_POLYNOMIAL_H_

#include "crypto/bls_wrapper.h"
#include <vector>
#include <cstdint>

class Polynomial {
public:
    explicit Polynomial(uint32_t threshold,
                        const FrNative& master_sk = FrNative());
    explicit Polynomial(const std::vector<FrNative>& coeffs);

    FrNative evaluate(uint32_t x) const;
    FrNative getSecret() const;
    const std::vector<FrNative>& getCoefficients() const { return coeffs_; }

    uint32_t degree() const {
        return static_cast<uint32_t>(coeffs_.size()) - 1;
    }
    uint32_t threshold() const { return degree() + 1; }

private:
    std::vector<FrNative> coeffs_;
};

#endif
