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


void EvaluateProtocol(encrypto::motion::PartyPointer& party, std::uint32_t value, std::uint32_t kValue) {
  // heavily inspired by millionaires problem
  
  std::cout << "Starting eval..." << std::flush;

  const std::size_t number_of_parties{party->GetConfiguration()->GetNumOfParties()};

  // (pre-)allocate indices and input values
  std::vector<mo::SecureUnsignedInteger> input_values(number_of_parties);

  // share inputs
  // remark: the input values to other parties' input gates are considered as buffers
  // and the values are simply ignored and overwritten later
  for (std::size_t i = 0; i < number_of_parties; ++i) {
    input_values[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(value), i);
  }
  
  // this does not work - "Invalid input owner: 2 of 2"
  // I guess we might introduce central party which inputs k?
  // mo::SecureUnsignedInteger secureK = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(kValue), number_of_parties);
  mo::SecureUnsignedInteger sum{input_values[0]};

  for (std::size_t i = 1; i != input_values.size(); ++i) {
    sum += input_values[i];
    // TODO DD: maybe tree-like addition?
  }

//  auto comparison = sum > secureK;

  mo::ShareWrapper& temp{sum.Get()};
  auto output = temp.Out();
 
  std::cout << "Running eval..." << std::flush;

  party->Run();
  party->Finish();

  std::cout << "Finished run..." << std::flush;

  // retrieve the result in binary form
  auto binary_output{output.As<std::vector<mo::BitVector<>>>()};
  // convert the binary result to integer
  auto result = mo::ToOutput<std::uint32_t>(binary_output);
  // print the result into the terminal
  std::cout << "Final sum: " << result  << std::flush;
}
