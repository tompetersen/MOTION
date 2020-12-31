// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "share_wrapper.h"

#include "algorithm/algorithm_description.h"
#include "algorithm/tree.h"
#include "base/backend.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_gate.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/bmr/bmr_gate.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/constant/constant_gate.h"
#include "protocols/constant/constant_share.h"
#include "protocols/constant/constant_wire.h"
#include "protocols/conversion/b2a_gate.h"
#include "protocols/conversion/conversion_gate.h"
#include "secure_type/secure_unsigned_integer.h"

namespace encrypto::motion {

using SharePointer = std::shared_ptr<Share>;

ShareWrapper ShareWrapper::operator~() const {
  assert(share_);
  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto gmw_share = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
    assert(gmw_share);
    auto inv_gate = std::make_shared<proto::boolean_gmw::InvGate>(gmw_share);
    share_->GetRegister()->RegisterNextGate(inv_gate);
    return ShareWrapper(inv_gate->GetOutputAsShare());
  } else {
    auto bmr_share = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
    assert(bmr_share);
    auto inv_gate = std::make_shared<proto::bmr::InvGate>(bmr_share);
    share_->GetRegister()->RegisterNextGate(inv_gate);
    return ShareWrapper(inv_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator^(const ShareWrapper& other) const {
  assert(share_);
  assert(*other);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto this_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
    auto other_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*other);

    assert(this_b);
    assert(other_b);

    auto xor_gate = std::make_shared<proto::boolean_gmw::XorGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  } else {
    auto this_b = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
    auto other_b = std::dynamic_pointer_cast<proto::bmr::Share>(*other);

    auto xor_gate = std::make_shared<proto::bmr::XorGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator&(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto this_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
    auto other_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*other);

    auto and_gate = std::make_shared<proto::boolean_gmw::AndGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(and_gate);
    return ShareWrapper(and_gate->GetOutputAsShare());
  } else {
    auto this_b = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
    auto other_b = std::dynamic_pointer_cast<proto::bmr::Share>(*other);

    auto and_gate = std::make_shared<proto::bmr::AndGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(and_gate);
    return ShareWrapper(and_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator|(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  // OR operatinos is equal to NOT ( ( NOT a ) AND ( NOT b ) )
  return ~((~*this) & ~other);
}

ShareWrapper ShareWrapper::operator+(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      other->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    return Add<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return Add<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return Add<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return Add<std::uint64_t>(share_, *other);
  } else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::operator-(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      other->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    return Sub<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return Sub<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return Sub<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return Sub<std::uint64_t>(share_, *other);
  } else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::operator*(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());
  assert(share_->GetNumberOfSimdValues() == other->GetNumberOfSimdValues());
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      other->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_ == other.share_) {  // squaring
    if (share_->GetBitLength() == 8u) {
      return Square<std::uint8_t>(share_);
    } else if (share_->GetBitLength() == 16u) {
      return Square<std::uint16_t>(share_);
    } else if (share_->GetBitLength() == 32u) {
      return Square<std::uint32_t>(share_);
    } else if (share_->GetBitLength() == 64u) {
      return Square<std::uint64_t>(share_);
    } else {
      throw std::bad_cast();
    }
  } else {
    if (share_->GetBitLength() == 8u) {
      return Mul<std::uint8_t>(share_, *other);
    } else if (share_->GetBitLength() == 16u) {
      return Mul<std::uint16_t>(share_, *other);
    } else if (share_->GetBitLength() == 32u) {
      return Mul<std::uint32_t>(share_, *other);
    } else if (share_->GetBitLength() == 64u) {
      return Mul<std::uint64_t>(share_, *other);
    } else {
      throw std::bad_cast();
    }
  }
}

ShareWrapper ShareWrapper::operator==(const ShareWrapper& other) const {
  if (other->GetBitLength() != share_->GetBitLength()) {
    share_->GetBackend().GetLogger()->LogError(
        fmt::format("Comparing shared bit strings of different bit lengths: this {} bits vs other "
                    "share's {} bits",
                    share_->GetBitLength(), other->GetBitLength()));
  } else if (other->GetBitLength() == 0) {
    share_->GetBackend().GetLogger()->LogError(
        "Comparing shared bit strings of bit length 0 is not allowed");
  }

  auto result = ~(*this ^ other);  // XNOR
  const auto bitlength = result->GetBitLength();

  if (bitlength == 1) {
    return result;
  } else if (IsPowerOfTwo(bitlength)) {
    return FullAndTree(result);
  } else {  // bitlength is not a power of 2
    while (result->GetBitLength() != 1) {
      std::queue<ShareWrapper> q;
      std::vector<ShareWrapper> output;
      std::size_t offset{0};
      const auto inner_bitlength{result->GetBitLength()};
      output.reserve(std::ceil(std::log2(inner_bitlength)));
      const auto split = result.Split();
      for (auto i = 1ull; i <= inner_bitlength; i *= 2) {
        if ((inner_bitlength & i) == i) {
          const auto _begin = split.begin() + offset;
          const auto _end = split.begin() + offset + i;
          q.push(ShareWrapper::Join(_begin, _end));
          offset += i;
        }
      }
      while (!q.empty()) {
        output.emplace_back(FullAndTree(q.front()));
        q.pop();
      }
      result = ShareWrapper::Join(output);
    }
    return result;
  }
}

ShareWrapper ShareWrapper::Mux(const ShareWrapper& a, const ShareWrapper& b) const {
  assert(*a);
  assert(*b);
  assert(share_);
  assert(share_->GetProtocol() == a->GetProtocol());
  assert(share_->GetProtocol() == b->GetProtocol());
  assert(a->GetBitLength() == b->GetBitLength());
  assert(share_->GetBitLength() == 1);

  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    // TODO implement
    throw std::runtime_error("C-OT-based Mux for Arithmetic GMW shares is not implemented yet");
  }

  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto this_gmw = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
    auto a_gmw = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*a);
    auto b_gmw = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*b);

    assert(this_gmw);
    assert(a_gmw);
    assert(b_gmw);

    auto mux_gate = std::make_shared<proto::boolean_gmw::MuxGate>(a_gmw, b_gmw, this_gmw);
    share_->GetRegister()->RegisterNextGate(mux_gate);
    return ShareWrapper(mux_gate->GetOutputAsShare());
  } else {
    // s ? a : b
    // result <- b ^ (s * (a ^ b))

    auto a_xor_b = a ^ b;

    auto mask = ShareWrapper::Join(std::vector<ShareWrapper>(a_xor_b->GetBitLength(), *this));
    mask &= a_xor_b;
    return b ^ mask;
  }
}

template <MpcProtocol P>
ShareWrapper ShareWrapper::Convert() const {
  constexpr auto kArithmeticGmw = MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = MpcProtocol::kBmr;
  if (share_->GetProtocol() == P) {
    throw std::runtime_error("Trying to convert share to MpcProtocol it is already in");
  }

  assert(share_->GetProtocol() < MpcProtocol::kInvalid);

  if constexpr (P == kArithmeticGmw) {
    if (share_->GetProtocol() == kBooleanGmw) {  // kBooleanGmw -> kArithmeticGmw
      return BooleanGmwToArithmeticGmw();
    } else {  // kBmr --(over kBooleanGmw)--> kArithmeticGmw
      return this->Convert<kBooleanGmw>().Convert<kArithmeticGmw>();
    }
  } else if constexpr (P == kBooleanGmw) {
    if (share_->GetProtocol() == kArithmeticGmw) {  // kArithmeticGmw --(over kBmr)--> kBooleanGmw
      return this->Convert<kBmr>().Convert<kBooleanGmw>();
    } else {  // kBmr -> kBooleanGmw
      return BmrToBooleanGmw();
    }
  } else if constexpr (P == kBmr) {
    if (share_->GetProtocol() == kArithmeticGmw) {  // kArithmeticGmw -> kBmr
      return ArithmeticGmwToBmr();
    } else {  // kBooleanGmw -> kBmr
      return BooleanGmwToBmr();
    }
  } else {
    throw std::runtime_error("Unkown MpcProtocol");
  }
}

// explicit specialization of function templates
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kArithmeticGmw>() const;
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kBooleanGmw>() const;
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kBmr>() const;

ShareWrapper ShareWrapper::ArithmeticGmwToBmr() const {
  auto arithmetic_gmw_to_bmr_gate{std::make_shared<ArithmeticGmwToBmrGate>(share_)};
  share_->GetRegister()->RegisterNextGate(arithmetic_gmw_to_bmr_gate);
  return ShareWrapper(arithmetic_gmw_to_bmr_gate->GetOutputAsShare());
}

ShareWrapper ShareWrapper::BooleanGmwToArithmeticGmw() const {
  const auto bitlength = share_->GetBitLength();
  switch (bitlength) {
    case 8u: {
      auto boolean_gmw_to_arithmetic_gmw_gate =
          std::make_shared<GmwToArithmeticGate<std::uint8_t>>(share_);
      share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    case 16u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          std::make_shared<GmwToArithmeticGate<std::uint16_t>>(share_)};
      share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    case 32u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          std::make_shared<GmwToArithmeticGate<std::uint32_t>>(share_)};
      share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    case 64u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          std::make_shared<GmwToArithmeticGate<std::uint64_t>>(share_)};
      share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    default:
      throw std::runtime_error(fmt::format("Invalid bitlength {}", bitlength));
  }
}

ShareWrapper ShareWrapper::BooleanGmwToBmr() const {
  auto boolean_gmw_share = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
  assert(boolean_gmw_share);
  auto boolean_gmw_to_bmr_gate{std::make_shared<BooleanGmwToBmrGate>(boolean_gmw_share)};
  share_->GetRegister()->RegisterNextGate(boolean_gmw_to_bmr_gate);
  return ShareWrapper(boolean_gmw_to_bmr_gate->GetOutputAsShare());
}

ShareWrapper ShareWrapper::BmrToBooleanGmw() const {
  auto bmr_share = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
  assert(bmr_share);
  auto bmr_to_boolean_gmw_gate = std::make_shared<BmrToBooleanGmwGate>(bmr_share);
  share_->GetRegister()->RegisterNextGate(bmr_to_boolean_gmw_gate);
  return ShareWrapper(bmr_to_boolean_gmw_gate->GetOutputAsShare());
}

const SharePointer ShareWrapper::Out(std::size_t output_owner) const {
  assert(share_);
  auto& backend = share_->GetBackend();
  switch (share_->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
      switch (share_->GetBitLength()) {
        case 8u: {
          return backend.ArithmeticGmwOutput<std::uint8_t>(share_, output_owner);
        }
        case 16u: {
          return backend.ArithmeticGmwOutput<std::uint16_t>(share_, output_owner);
        }
        case 32u: {
          return backend.ArithmeticGmwOutput<std::uint32_t>(share_, output_owner);
        }
        case 64u: {
          return backend.ArithmeticGmwOutput<std::uint64_t>(share_, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength())));
        }
      }
    }
    case MpcProtocol::kBooleanGmw: {
      return backend.BooleanGmwOutput(share_, output_owner);
    }
    case MpcProtocol::kBmr: {
      return backend.BmrOutput(share_, output_owner);
    }
    default: {
      throw(std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
                                           static_cast<uint>(share_->GetProtocol()))));
    }
  }
}

std::vector<ShareWrapper> ShareWrapper::Split() const {
  std::vector<ShareWrapper> result;
  result.reserve(share_->GetWires().size());
  const auto split = share_->Split();
  for (const auto& s : split) result.emplace_back(s);
  return result;
}

ShareWrapper ShareWrapper::Join(const std::vector<ShareWrapper>& shares) {
  if (shares.empty()) throw std::runtime_error("ShareWrapper cannot be empty");
  {
    const auto protocol = shares.at(0)->GetProtocol();
    for (auto i = 1ull; i < shares.size(); ++i) {
      if (shares.at(i)->GetProtocol() != protocol) {
        throw std::runtime_error("Trying to join shares of different types");
      }
    }
  }
  std::vector<SharePointer> unwrapped_shares;
  unwrapped_shares.reserve(shares.size());
  for (const auto& s : shares) unwrapped_shares.emplace_back(*s);

  std::size_t bit_size_wires{0};
  for (const auto& s : shares) bit_size_wires += s->GetBitLength();

  std::vector<WirePointer> wires;
  wires.reserve(bit_size_wires);
  for (const auto& s : shares)
    for (const auto& w : s->GetWires()) wires.emplace_back(w);
  switch (shares.at(0)->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
      switch (wires.at(0)->GetBitLength()) {
        case 8: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint8_t>>(wires));
        }
        case 16: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint16_t>>(wires));
        }
        case 32: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint32_t>>(wires));
        }
        case 64: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint64_t>>(wires));
        }
        default:
          throw std::runtime_error(fmt::format(
              "Incorrect bit length of arithmetic shares: {}, allowed are 8, 16, 32, 64",
              wires.at(0)->GetBitLength()));
      }
    }
    case MpcProtocol::kBooleanGmw: {
      return ShareWrapper(std::make_shared<proto::boolean_gmw::Share>(wires));
    }
    case MpcProtocol::kBmr: {
      return ShareWrapper(std::make_shared<proto::bmr::Share>(wires));
    }
    default: {
      throw std::runtime_error("Unknown MPC protocol");
    }
  }
}

ShareWrapper ShareWrapper::Evaluate(const AlgorithmDescription& algorithm) const {
  std::size_t number_of_input_wires = algorithm.number_of_input_wires_parent_a;
  if (algorithm.number_of_input_wires_parent_b)
    number_of_input_wires += *algorithm.number_of_input_wires_parent_b;

  if (number_of_input_wires != share_->GetBitLength()) {
    share_->GetRegister()->GetLogger()->LogError(fmt::format(
        "ShareWrapper::Evaluate: expected a share of bit length {}, got a share of bit length {}",
        number_of_input_wires, share_->GetBitLength()));
  }

  auto share_split_in_wires{Split()};
  std::vector<std::shared_ptr<ShareWrapper>> pointers_to_wires_of_split_share;
  pointers_to_wires_of_split_share.reserve(share_split_in_wires.size());
  for (const auto& w : share_split_in_wires)
    pointers_to_wires_of_split_share.emplace_back(std::make_shared<ShareWrapper>(w.Get()));

  pointers_to_wires_of_split_share.resize(algorithm.number_of_wires, nullptr);

  assert((algorithm.number_of_gates + number_of_input_wires) ==
         pointers_to_wires_of_split_share.size());

  for (std::size_t wire_i = number_of_input_wires, gate_i = 0; wire_i < algorithm.number_of_wires;
       ++wire_i, ++gate_i) {
    const auto& gate = algorithm.gates.at(gate_i);
    const auto type = gate.type;
    switch (type) {
      case PrimitiveOperationType::kXor: {
        assert(gate.parent_b);
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(*pointers_to_wires_of_split_share.at(gate.parent_a) ^
                                           *pointers_to_wires_of_split_share.at(*gate.parent_b));
        break;
      }
      case PrimitiveOperationType::kAnd: {
        assert(gate.parent_b);
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(*pointers_to_wires_of_split_share.at(gate.parent_a) &
                                           *pointers_to_wires_of_split_share.at(*gate.parent_b));
        break;
      }
      case PrimitiveOperationType::kOr: {
        assert(gate.parent_b);
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(*pointers_to_wires_of_split_share.at(gate.parent_a) |
                                           *pointers_to_wires_of_split_share.at(*gate.parent_b));
        break;
      }
      case PrimitiveOperationType::kInv: {
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(~*pointers_to_wires_of_split_share.at(gate.parent_a));
        break;
      }
      default:
        throw std::runtime_error("Invalid PrimitiveOperationType");
    }
  }

  std::vector<ShareWrapper> output;
  output.reserve(pointers_to_wires_of_split_share.size() - algorithm.number_of_output_wires);
  for (auto i = pointers_to_wires_of_split_share.size() - algorithm.number_of_output_wires;
       i < pointers_to_wires_of_split_share.size(); i++) {
    output.emplace_back(*pointers_to_wires_of_split_share.at(i));
  }

  return ShareWrapper::Join(output);
}

template <typename T>
ShareWrapper ShareWrapper::Add(SharePointer share, SharePointer other) const {
  if (!share->IsConstant() && !other->IsConstant()) {
    auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
    assert(this_a);
    auto this_wire_a = this_a->GetArithmeticWire();

    auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
    assert(other_a);
    auto other_wire_a = other_a->GetArithmeticWire();

    auto addition_gate =
        std::make_shared<proto::arithmetic_gmw::AdditionGate<T>>(this_wire_a, other_wire_a);
    auto addition_gate_cast = std::static_pointer_cast<Gate>(addition_gate);
    share_->GetRegister()->RegisterNextGate(addition_gate_cast);
    auto result = std::static_pointer_cast<Share>(addition_gate->GetOutputAsArithmeticShare());

    return ShareWrapper(result);
  } else {
    assert(!(share->IsConstant() && other->IsConstant()));
    auto constant_wire_original = share;
    auto non_constant_wire_original = other;
    if (non_constant_wire_original->IsConstant())
      std::swap(constant_wire_original, non_constant_wire_original);
    assert(constant_wire_original->IsConstant() && !non_constant_wire_original->IsConstant());

    auto constant_wire = std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(
        constant_wire_original->GetWires()[0]);
    assert(constant_wire);
    auto non_constant_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
        non_constant_wire_original->GetWires()[0]);
    assert(non_constant_wire);

    auto addition_gate = std::make_shared<proto::ConstantArithmeticAdditionGate<T>>(
        non_constant_wire, constant_wire);
    share_->GetRegister()->RegisterNextGate(addition_gate);
    auto result = std::static_pointer_cast<Share>(addition_gate->GetOutputAsArithmeticShare());

    return ShareWrapper(result);
  }
}

template ShareWrapper ShareWrapper::Add<std::uint8_t>(SharePointer share, SharePointer other) const;
template ShareWrapper ShareWrapper::Add<std::uint16_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Add<std::uint32_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Add<std::uint64_t>(SharePointer share,
                                                       SharePointer other) const;

template <typename T>
ShareWrapper ShareWrapper::Sub(SharePointer share, SharePointer other) const {
  auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
  assert(other_a);
  auto other_wire_a = other_a->GetArithmeticWire();

  auto subtraction_gate =
      std::make_shared<proto::arithmetic_gmw::SubtractionGate<T>>(this_wire_a, other_wire_a);
  auto addition_gate_cast = std::static_pointer_cast<Gate>(subtraction_gate);
  share_->GetRegister()->RegisterNextGate(addition_gate_cast);
  auto result = std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsArithmeticShare());

  return ShareWrapper(result);
}

template ShareWrapper ShareWrapper::Sub<std::uint8_t>(SharePointer share, SharePointer other) const;
template ShareWrapper ShareWrapper::Sub<std::uint16_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Sub<std::uint32_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Sub<std::uint64_t>(SharePointer share,
                                                       SharePointer other) const;

template <typename T>
ShareWrapper ShareWrapper::Mul(SharePointer share, SharePointer other) const {
  if (!share->IsConstant() && !other->IsConstant()) {
    auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
    assert(this_a);
    auto this_wire_a = this_a->GetArithmeticWire();

    auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
    assert(other_a);
    auto other_wire_a = other_a->GetArithmeticWire();

    auto multiplication_gate =
        std::make_shared<proto::arithmetic_gmw::MultiplicationGate<T>>(this_wire_a, other_wire_a);
    share_->GetRegister()->RegisterNextGate(multiplication_gate);
    auto result =
        std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsArithmeticShare());

    return ShareWrapper(result);
  } else {
    assert(!(share->IsConstant() && other->IsConstant()));
    auto constant_wire_original = share;
    auto non_constant_wire_original = other;
    if (non_constant_wire_original->IsConstant())
      std::swap(constant_wire_original, non_constant_wire_original);
    assert(constant_wire_original->IsConstant() && !non_constant_wire_original->IsConstant());

    auto constant_wire = std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(
        constant_wire_original->GetWires()[0]);
    assert(constant_wire);
    auto non_constant_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
        non_constant_wire_original->GetWires()[0]);
    assert(non_constant_wire);

    auto multiplication_gate = std::make_shared<proto::ConstantArithmeticMultiplicationGate<T>>(
        non_constant_wire, constant_wire);
    share_->GetRegister()->RegisterNextGate(multiplication_gate);
    auto result =
        std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsArithmeticShare());

    return ShareWrapper(result);
  }
}

template <typename T>
ShareWrapper ShareWrapper::Square(SharePointer share) const {
  auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto square_gate = std::make_shared<proto::arithmetic_gmw::SquareGate<T>>(this_wire_a);
  auto square_gate_cast = std::static_pointer_cast<Gate>(square_gate);
  share_->GetRegister()->RegisterNextGate(square_gate_cast);
  auto result = std::static_pointer_cast<Share>(square_gate->GetOutputAsArithmeticShare());

  return ShareWrapper(result);
}

template ShareWrapper ShareWrapper::Mul<std::uint8_t>(SharePointer share, SharePointer other) const;
template ShareWrapper ShareWrapper::Mul<std::uint16_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Mul<std::uint32_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Mul<std::uint64_t>(SharePointer share,
                                                       SharePointer other) const;

}  // namespace encrypto::motion
