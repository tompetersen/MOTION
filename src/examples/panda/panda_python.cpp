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

#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>

#include "base/party.h"
#include "common/panda.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>  // suppport for STL containers


namespace py = pybind11;

std::vector<uint32_t> perform(std::vector<std::tuple<std::size_t, std::string, std::uint16_t>> parties, std::size_t my_id, std::vector<uint32_t> inputs, uint32_t k) {
  const auto number_of_parties{parties.size()};
  
  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, number_of_parties));
  }
  
  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

  for (const auto party : parties) {
    const std::size_t party_id = std::get<0>(party);
    const std::string host = std::get<1>(party);
    const std::uint16_t port = std::get<2>(party);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(
          fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }

  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  configuration->SetLoggingEnabled(false);

  auto results = EvaluateProtocol(party, inputs, k);

  return results;
}


uint32_t getZeroMaskValue() {
  return GetZeroMaskValue();
}


PYBIND11_MODULE(pandapython, m) {
    m.doc() = "pybind11 example plugin"; // optional module docstring

    m.def("perform", &perform, "Perform parallel sum>k mpc protocol",
    py::arg("parties"), py::arg("my_id"), py::arg("my_inputs"), py::arg("k"));

    m.def("get_zero_mask_value", &getZeroMaskValue, "The value a zero sum is masked with... for internal reasons -,-");
}

