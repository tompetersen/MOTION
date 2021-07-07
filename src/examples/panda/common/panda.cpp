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

#include "panda.h"

#include <cstddef>
#include <vector>
#include <limits>

#include "algorithm/algorithm_description.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/config.h"



namespace mo = encrypto::motion;


std::vector<bool> EvaluateProtocol(encrypto::motion::PartyPointer& party, std::vector<std::uint32_t> values, std::uint32_t kValue) {
  // heavily inspired by millionaires problem
  
  std::cout << "Starting eval..." << std::endl;

  const std::size_t number_of_parties{party->GetConfiguration()->GetNumOfParties()};
  const std::size_t number_of_inputs{values.size()};

  std::cout << "Before input_values init (parties: " << number_of_parties << ", values: " << number_of_inputs << ")..." << std::endl;

  // (pre-)allocate indices and input values
  std::vector<std::vector<mo::SecureUnsignedInteger>> input_values(number_of_parties);

  // share inputs
  // remark: the input values to other parties' input gates are considered as buffers
  // and the values are simply ignored and overwritten later
  for (std::size_t i = 0; i < number_of_parties; ++i) {
    std::vector<mo::SecureUnsignedInteger> tmp(number_of_inputs);
    for (std::size_t j = 0; j < number_of_inputs; ++j) {
      tmp[j] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(values[j]), i);
    }
    input_values[i] = tmp;
  }

  // we might introduce central party which inputs k?
  mo::SecureUnsignedInteger secureK = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(kValue), 0);
 
  std::vector<mo::SecureUnsignedInteger> sums(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    sums[j] = input_values[0][j];
  }

  for (std::size_t i = 1; i != input_values.size(); ++i) {
    for (std::size_t j = 0; j < number_of_inputs; ++j) {
      sums[j] += input_values[i][j];
      // TODO DD: maybe tree-like addition?
    }
  }

  std::vector<mo::ShareWrapper> comparisons(number_of_inputs);

  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    comparisons[j] = sums[j] > secureK;
  }

//  mo::ShareWrapper& temp{sum.Get()};
//  auto output = temp.Out();

  std::vector<mo::ShareWrapper> outputs(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    outputs[j] = comparisons[j].Out();
  }
 
  std::cout << "Running eval..." << std::endl;

  party->Run();
  party->Finish();

  std::cout << "Finished run. Results: " << std::endl;

  std::vector<bool> results(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    // retrieve the result in boolean form
    auto result{outputs[j].As<bool>()};
    results[j] = result;

    std::cout << " " << result;
  }

  return results;
}
