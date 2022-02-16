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
#include "statistics/analysis.h"


namespace mo = encrypto::motion;


std::vector<uint32_t> EvaluateProtocolBasic(encrypto::motion::PartyPointer& party, std::vector<std::uint32_t> values, std::uint32_t kValue) {
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

  // TODO use arithmetic circuit for additions and transform to boolean for comparison?
  // TODO maybe it would be better to introduce k, zero and zeroMask values number_of_inputs times for separated parallelizable circuits?
  
  // we might introduce central party which inputs k?
  mo::SecureUnsignedInteger secureK = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(kValue), 0);

  // we mask sums equal to 0 with MAX to distinguish the cases 0, < k and >= k
  uint32_t zeroMask = GetZeroMaskValue();
  mo::SecureUnsignedInteger secureZeroMask = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zeroMask), 0);

  // we mask sums smaller than k with 0, leaking no info
  uint32_t zero = 0;
  mo::SecureUnsignedInteger secureZero = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 0);
 
  // compute sums
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

  // perform comparisons
  std::vector<mo::ShareWrapper> comparisons(number_of_inputs);

  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    // we perform the check for zero first to distinguish between zero and less than k  
    // result = sum == 0 ? zeroMask : sum  
    mo::ShareWrapper comparison1 = sums[j] == secureZero;
    comparisons[j] = comparison1.Mux(secureZeroMask.Get(), sums[j].Get());
    // result = k > result ? 0 : result
    mo::ShareWrapper comparison2 = secureK > comparisons[j];
    comparisons[j] = comparison2.Mux(secureZero.Get(), comparisons[j].Get());
  }

  // output gates
  std::vector<mo::ShareWrapper> outputs(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    outputs[j] = comparisons[j].Out();
  }
 
  std::cout << "Running eval..." << std::endl;

  party->Run();
  party->Finish();

  //performance statistics
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;

  const auto& statistics = party->GetBackend()->GetRunTimeStatistics(); // /src/motioncore/statistics/run_time_statistics.h
  const auto unclear = statistics.front();
  const auto communcation_statistics = party->GetCommunicationLayer().GetTransportStatistics(); // panda/src/motioncore/communication/transport.h

  accumulated_statistics.Add(unclear);
  accumulated_communication_statistics.Add(communcation_statistics);


  if (party->GetCommunicationLayer().GetMyId() == 0) {
      std::cout << encrypto::motion::PrintStatistics("Statistics", accumulated_statistics, accumulated_communication_statistics) << std::endl;
  }

  std::cout << "Finished run. Results: " << std::endl;

  //convert results from binary to int
  std::vector<uint32_t> results(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    auto binary_output{outputs[j].As<std::vector<mo::BitVector<>>>()};
    auto result = mo::ToOutput<std::uint32_t>(binary_output);
    results[j] = result;

    std::cout << " " << result;
  }

  return results;
}

std::vector<uint32_t> EvaluateProtocolTreeAdditionParted(encrypto::motion::PartyPointer& party, std::vector<std::uint32_t> values, std::uint32_t kValue) {
  // use the same principle as in https://github.com/encryptogroup/ABY/blob/public/src/abycore/circuit/booleancircuits.cpp#L1968-L1997

  // heavily inspired by millionaires problem
  
  std::cout << "Starting eval..." << std::endl;

  const std::size_t numberOfParties{party->GetConfiguration()->GetNumOfParties()};
  const std::size_t numberOfInputs{values.size()};

  std::cout << "Before inputValues init (parties: " << numberOfParties << ", values: " << numberOfInputs << ")..." << std::endl;

  // (pre-)allocate indices and input values
  std::vector<std::vector<mo::SecureUnsignedInteger>> inputValues(numberOfInputs);

  // share inputs
  // remark: the input values to other parties' input gates are considered as buffers
  // and the values are simply ignored and overwritten later
  //
  // ATTENTION: we have changed the order of inputs and parties here!
  for (std::size_t i = 0; i < numberOfInputs; ++i) {
    std::vector<mo::SecureUnsignedInteger> tmp(numberOfParties);
    for (std::size_t j = 0; j < numberOfParties; ++j) {
      tmp[j] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(values[i]), j);
    }
    inputValues[i] = tmp;
  }

  // TODO use arithmetic circuit for additions and transform to boolean for comparison?
  // TODO maybe it would be better to introduce k, zero and zeroMask values numberOfInputs times for separated parallelizable circuits?
  
  // we might introduce central party which inputs k?
  std::vector<mo::SecureUnsignedInteger> secureK(numberOfInputs);
  for (std::size_t i = 0; i < numberOfInputs; i++) {
      secureK[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(kValue), 0);
  }

  // we mask sums equal to 0 with MAX to distinguish the cases 0, < k and >= k
  uint32_t zeroMask = zeroMaskValue();
  std::vector<mo::SecureUnsignedInteger> secureZeroMask(numberOfInputs);
  for (std::size_t i = 0; i < numberOfInputs; i++) {
      secureZeroMask[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zeroMask), 0);
  }

  // we mask sums smaller than k with 0, leaking no info
  uint32_t zero = 0;
  std::vector<mo::SecureUnsignedInteger> secureZero(numberOfInputs);
  for (std::size_t i = 0; i < numberOfInputs; i++) {
      secureZero[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 0);
  }




  // compute sums
  std::vector<mo::SecureUnsignedInteger> sums(numberOfInputs);

  for (std::size_t k = 0; k < numberOfInputs; ++k) {
      // build balanced binary tree for each input
      std::vector<mo::SecureUnsignedInteger> single_input = inputValues[k];
      while (single_input.size() > 1) {
          unsigned j = 0;
          for (unsigned i = 0; i < single_input.size();) {
              if (i + 1 >= single_input.size()) { //place single element at vector end
                  single_input[j] = single_input[i];
                  i++;
              } 
              else { //add two elements
                  single_input[j] = single_input[i + 1] + single_input[i];
                  i += 2;
              }
              j++;
          }
          single_input.resize(j);
      }
      sums[k] = single_input[0];
  }



  // perform comparisons
  std::vector<mo::ShareWrapper> comparisons(numberOfInputs);

  for (std::size_t j = 0; j < numberOfInputs; ++j) {
    // we perform the check for zero first to distinguish between zero and less than k  
    // result = sum == 0 ? zeroMask : sum  
    mo::ShareWrapper comparison1 = sums[j] == secureZero[j];
    comparisons[j] = comparison1.Mux(secureZeroMask[j].Get(), sums[j].Get());
    // result = k > result ? 0 : result
    mo::ShareWrapper comparison2 = secureK[j] > comparisons[j];
    comparisons[j] = comparison2.Mux(secureZero[j].Get(), comparisons[j].Get());
  }

  // output gates
  std::vector<mo::ShareWrapper> outputs(numberOfInputs);
  for (std::size_t j = 0; j < numberOfInputs; ++j) {
    outputs[j] = comparisons[j].Out();
  }
 
  std::cout << "Running eval..." << std::endl;

  party->Run();
  party->Finish();

  //performance statistics
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;

  const auto& statistics = party->GetBackend()->GetRunTimeStatistics(); // /src/motioncore/statistics/run_time_statistics.h
  const auto unclear = statistics.front();
  const auto communcation_statistics = party->GetCommunicationLayer().GetTransportStatistics(); // panda/src/motioncore/communication/transport.h

  accumulated_statistics.Add(unclear);
  accumulated_communication_statistics.Add(communcation_statistics);


  if (party->GetCommunicationLayer().GetMyId() == 0) {
      std::cout << encrypto::motion::PrintStatistics("Statistics", accumulated_statistics, accumulated_communication_statistics) << std::endl;
  }

  std::cout << "Finished run. Results: " << std::endl;

  //convert results from binary to int
  std::vector<uint32_t> results(numberOfInputs);
  for (std::size_t j = 0; j < numberOfInputs; ++j) {
    auto binary_output{outputs[j].As<std::vector<mo::BitVector<>>>()};
    auto result = mo::ToOutput<std::uint32_t>(binary_output);
    results[j] = result;

    std::cout << " " << result;
  }

  return results;
}


std::vector<uint32_t> EvaluateProtocolTreeAddition(encrypto::motion::PartyPointer& party, std::vector<std::uint32_t> values, std::uint32_t kValue) {
  // use the same principle as in https://github.com/encryptogroup/ABY/blob/public/src/abycore/circuit/booleancircuits.cpp#L1968-L1997

  // heavily inspired by millionaires problem
  
  std::cout << "Starting eval..." << std::endl;

  const std::size_t number_of_parties{party->GetConfiguration()->GetNumOfParties()};
  const std::size_t number_of_inputs{values.size()};

  std::cout << "Before input_values init (parties: " << number_of_parties << ", values: " << number_of_inputs << ")..." << std::endl;

  // (pre-)allocate indices and input values
  std::vector<std::vector<mo::SecureUnsignedInteger>> input_values(number_of_inputs);

  // share inputs
  // remark: the input values to other parties' input gates are considered as buffers
  // and the values are simply ignored and overwritten later
  //
  // ATTENTION: we have changed the order of inputs and parties here!
  for (std::size_t i = 0; i < number_of_inputs; ++i) {
    std::vector<mo::SecureUnsignedInteger> tmp(number_of_parties);
    for (std::size_t j = 0; j < number_of_parties; ++j) {
      tmp[j] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(values[i]), j);
    }
    input_values[i] = tmp;
  }

  // TODO use arithmetic circuit for additions and transform to boolean for comparison?
  // TODO maybe it would be better to introduce k, zero and zeroMask values number_of_inputs times for separated parallelizable circuits?
  
  // we might introduce central party which inputs k?
  mo::SecureUnsignedInteger secureK = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(kValue), 0);

  // we mask sums equal to 0 with MAX to distinguish the cases 0, < k and >= k
  uint32_t zeroMask = GetZeroMaskValue();
  mo::SecureUnsignedInteger secureZeroMask = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zeroMask), 0);

  // we mask sums smaller than k with 0, leaking no info
  uint32_t zero = 0;
  mo::SecureUnsignedInteger secureZero = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 0);




  // compute sums
  std::vector<mo::SecureUnsignedInteger> sums(number_of_inputs);

  for (std::size_t k = 0; k < number_of_inputs; ++k) {
      // build balanced binary tree for each input
      std::vector<mo::SecureUnsignedInteger> single_input = input_values[k];
      while (single_input.size() > 1) {
          unsigned j = 0;
          for (unsigned i = 0; i < single_input.size();) {
              if (i + 1 >= single_input.size()) { //place single element at vector end
                  single_input[j] = single_input[i];
                  i++;
              } 
              else { //add two elements
                  single_input[j] = single_input[i + 1] + single_input[i];
                  i += 2;
              }
              j++;
          }
          single_input.resize(j);
      }
      sums[k] = single_input[0];
  }



  // perform comparisons
  std::vector<mo::ShareWrapper> comparisons(number_of_inputs);

  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    // we perform the check for zero first to distinguish between zero and less than k  
    // result = sum == 0 ? zeroMask : sum  
    mo::ShareWrapper comparison1 = sums[j] == secureZero;
    comparisons[j] = comparison1.Mux(secureZeroMask.Get(), sums[j].Get());
    // result = k > result ? 0 : result
    mo::ShareWrapper comparison2 = secureK > comparisons[j];
    comparisons[j] = comparison2.Mux(secureZero.Get(), comparisons[j].Get());
  }

  // output gates
  std::vector<mo::ShareWrapper> outputs(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    outputs[j] = comparisons[j].Out();
  }
 
  std::cout << "Running eval..." << std::endl;

  party->Run();
  party->Finish();

  //performance statistics
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;

  const auto& statistics = party->GetBackend()->GetRunTimeStatistics(); // /src/motioncore/statistics/run_time_statistics.h
  const auto unclear = statistics.front();
  const auto communcation_statistics = party->GetCommunicationLayer().GetTransportStatistics(); // panda/src/motioncore/communication/transport.h

  accumulated_statistics.Add(unclear);
  accumulated_communication_statistics.Add(communcation_statistics);


  if (party->GetCommunicationLayer().GetMyId() == 0) {
      std::cout << encrypto::motion::PrintStatistics("Statistics", accumulated_statistics, accumulated_communication_statistics) << std::endl;
  }

  std::cout << "Finished run. Results: " << std::endl;

  //convert results from binary to int
  std::vector<uint32_t> results(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    auto binary_output{outputs[j].As<std::vector<mo::BitVector<>>>()};
    auto result = mo::ToOutput<std::uint32_t>(binary_output);
    results[j] = result;

    std::cout << " " << result;
  }

  return results;
}

std::vector<uint32_t> EvaluateProtocolArithmeticThenBool(encrypto::motion::PartyPointer& party, std::vector<std::uint32_t> values, std::uint32_t kValue) {
  // heavily inspired by millionaires problem
  
  std::cout << "Starting eval..." << std::endl;

  const std::size_t number_of_parties{party->GetConfiguration()->GetNumOfParties()};
  const std::size_t number_of_inputs{values.size()};

  std::cout << "Before input_values init (parties: " << number_of_parties << ", values: " << number_of_inputs << ")..." << std::endl;

  // (pre-)allocate indices and input values
  std::vector<std::vector<mo::SecureUnsignedInteger>> input_values(number_of_inputs);

  // share inputs
  // remark: the input values to other parties' input gates are considered as buffers
  // and the values are simply ignored and overwritten later
  //
  // ATTENTION: we have changed the order of inputs and parties here!
  for (std::size_t i = 0; i < number_of_inputs; ++i) {
    std::vector<mo::SecureUnsignedInteger> tmp(number_of_parties);
    for (std::size_t j = 0; j < number_of_parties; ++j) {
      // tmp[j] = party->In<mo::MpcProtocol::kArithmeticGmw>(mo::ToInput(values[i]), j);
      tmp[j] = party->In<mo::MpcProtocol::kArithmeticGmw>(values[i], j);
    }
    input_values[i] = tmp;
  }

  // TODO use arithmetic circuit for additions and transform to boolean for comparison?
  // TODO maybe it would be better to introduce k, zero and zeroMask values number_of_inputs times for separated parallelizable circuits?
  
  // we might introduce central party which inputs k?
  mo::SecureUnsignedInteger secureK = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(kValue), 0);

  // we mask sums equal to 0 with MAX to distinguish the cases 0, < k and >= k
  uint32_t zeroMask = GetZeroMaskValue();
  mo::SecureUnsignedInteger secureZeroMask = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zeroMask), 0);

  // we mask sums smaller than k with 0, leaking no info
  uint32_t zero = 0;
  mo::SecureUnsignedInteger secureZero = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 0);




  // compute sums
  std::vector<mo::SecureUnsignedInteger> sums(number_of_inputs);

  for (std::size_t k = 0; k < number_of_inputs; ++k) {
      // build balanced binary tree for each input
      std::vector<mo::SecureUnsignedInteger> single_input = input_values[k];
      while (single_input.size() > 1) {
          unsigned j = 0;
          for (unsigned i = 0; i < single_input.size();) {
              if (i + 1 >= single_input.size()) { //place single element at vector end
                  single_input[j] = single_input[i];
                  i++;
              } 
              else { //add two elements
                  single_input[j] = single_input[i + 1] + single_input[i];
                  i += 2;
              }
              j++;
          }
          single_input.resize(j);
      }
      sums[k] = single_input[0];
  }



  //convert kArithmetic to kBoolean
  for (std::size_t i = 0; i < sums.size(); i++) {
      mo::ShareWrapper share_input(sums[i].Get());
      mo::ShareWrapper share_conversion{share_input.Convert<mo::MpcProtocol::kBooleanGmw>()};
      mo::SecureUnsignedInteger tmp_sui(share_conversion);
      sums[i] = tmp_sui;
  }




  // perform comparisons
  std::vector<mo::ShareWrapper> comparisons(number_of_inputs);

  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    // we perform the check for zero first to distinguish between zero and less than k  
    // result = sum == 0 ? zeroMask : sum  
    mo::ShareWrapper comparison1 = sums[j] == secureZero;
    comparisons[j] = comparison1.Mux(secureZeroMask.Get(), sums[j].Get());
    // result = k > result ? 0 : result
    mo::ShareWrapper comparison2 = secureK > comparisons[j];
    comparisons[j] = comparison2.Mux(secureZero.Get(), comparisons[j].Get());
  }

  // output gates
  std::vector<mo::ShareWrapper> outputs(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    outputs[j] = comparisons[j].Out();
  }
 
  std::cout << "Running eval..." << std::endl;

  party->Run();
  party->Finish();

  //performance statistics
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;

  const auto& statistics = party->GetBackend()->GetRunTimeStatistics(); // /src/motioncore/statistics/run_time_statistics.h
  const auto unclear = statistics.front();
  const auto communcation_statistics = party->GetCommunicationLayer().GetTransportStatistics(); // panda/src/motioncore/communication/transport.h

  accumulated_statistics.Add(unclear);
  accumulated_communication_statistics.Add(communcation_statistics);


  if (party->GetCommunicationLayer().GetMyId() == 0) {
      std::cout << encrypto::motion::PrintStatistics("Statistics", accumulated_statistics, accumulated_communication_statistics) << std::endl;
  }

  std::cout << "Finished run. Results: " << std::endl;

  //convert results from binary to int
  std::vector<uint32_t> results(number_of_inputs);
  for (std::size_t j = 0; j < number_of_inputs; ++j) {
    auto binary_output{outputs[j].As<std::vector<mo::BitVector<>>>()};
    auto result = mo::ToOutput<std::uint32_t>(binary_output);
    results[j] = result;

    std::cout << " " << result;
  }

  return results;
}

uint32_t GetZeroMaskValue() {
    //TODO There seems to be a bug in MOTION
    // cmp = uint32_t.max() > 5 
    // cmp.mux(a, b) 
    //   -> b
    // Therefore we use a slightly smaller value here, which should be large
    // enough to never occur in practice anyway.

    return std::numeric_limits<uint32_t>::max() / 4;
}
