// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <vector>

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    std::map< uint64_t, crypto::hash >::const_iterator highest = 
        std::max_element( m_points.begin(), m_points.end(),
                         ( boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _1) < 
                           boost::bind(&std::map< uint64_t, crypto::hash >::value_type::first, _2 ) ) );
    return highest->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    /*
    if (nettype == TESTNET)
    {
      ADD_CHECKPOINT(0,     "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b");
      ADD_CHECKPOINT(1000000, "46b690b710a07ea051bc4a6b6842ac37be691089c0f7758cfeec4d5fc0b4a258");
      ADD_CHECKPOINT(1058600, "12904f6b4d9e60fd875674e07147d2c83d6716253f046af7b894c3e81da7e1bd");
      return true;
    }
    if (nettype == STAGENET)
    {
      ADD_CHECKPOINT(0,       "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb");
      ADD_CHECKPOINT(10000,   "1f8b0ce313f8b9ba9a46108bfd285c45ad7c2176871fd41c3a690d4830ce2fd5");
      return true;
    }*/
    ADD_CHECKPOINT(1,     "fbb3f0e217f37c3f4f3b46b7816827b5bc5a23ed8c92cb4a717e06725680677f");
    ADD_CHECKPOINT(1000,    "b800b5056bfd2ad9a430803c99e837812557745aadf8ba2bc3486dbf681493b9");
    ADD_CHECKPOINT(5000,   "f0d38c8ed745d0d32688040bd959e5fabc433fb41536f4169648488859806647");
    ADD_CHECKPOINT(10000,  "f89ed960be38bdd9aa817935aaf4f73578970d98e02a4272e2febfef1e183e3a");
    ADD_CHECKPOINT(20000, "2a83db69e5e9fdbd6d2377073bd4c8c1fe709e70349fecbda08c9d21accdc9ba");
    ADD_CHECKPOINT(40000, "96b44eb190d324f753be8f4f1748f862f964bd2fa527664c79d9a15496b8bf51");
    ADD_CHECKPOINT(71200, "d25f97ac52c679a95b41567a0f49e2cc3faabd8f25f1de1125662554e036f021");
    ADD_CHECKPOINT(100000, "6b24f86d9086595c4f28584a303a47731fb83434eb0b54040ee70b29f9332237");
    ADD_CHECKPOINT(130000, "8245309464714a59ba120efc73def198e122e0b26d605028eca47495de63aaa3");
    ADD_CHECKPOINT(160000, "eb0a1509c46bac98a5a4dcfa2a667eedde1577f23c88cbe72bcde77b66374156");
    ADD_CHECKPOINT(200000, "c28f15abcbd506817c5b515a6c701cf4c0d7d7ca68d249058c7034b7d1dac9b0");
    /*ADD_CHECKPOINT(50000, "0fe8758ab06a8b9cb35b7328fd4f757af530a5d37759f9d3e421023231f7b31c");
    ADD_CHECKPOINT(80000, "a62dcd7b536f22e003ebae8726e9e7276f63d594e264b6f0cd7aab27b66e75e3");
    ADD_CHECKPOINT(202612, "bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698");
    ADD_CHECKPOINT(202613, "e2aa337e78df1f98f462b3b1e560c6b914dec47b610698b7b7d1e3e86b6197c2");
    ADD_CHECKPOINT(202614, "c29e3dc37d8da3e72e506e31a213a58771b24450144305bcba9e70fa4d6ea6fb");
    ADD_CHECKPOINT(205000, "5d3d7a26e6dc7535e34f03def711daa8c263785f73ec1fadef8a45880fde8063");
    ADD_CHECKPOINT(220000, "9613f455933c00e3e33ac315cc6b455ee8aa0c567163836858c2d9caff111553");
    ADD_CHECKPOINT(230300, "bae7a80c46859db355556e3a9204a337ae8f24309926a1312323fdecf1920e61");
    ADD_CHECKPOINT(230700, "93e631240ceac831da1aebfc5dac8f722c430463024763ebafa888796ceaeedf");
    ADD_CHECKPOINT(231350, "b5add137199b820e1ea26640e5c3e121fd85faa86a1e39cf7e6cc097bdeb1131");
    ADD_CHECKPOINT(232150, "955de8e6b6508af2c24f7334f97beeea651d78e9ade3ab18fec3763be3201aa8");
    ADD_CHECKPOINT(249380, "654fb0a81ce3e5caf7e3264a70f447d4bd07586c08fa50f6638cc54da0a52b2d");
    ADD_CHECKPOINT(460000, "75037a7aed3e765db96c75bcf908f59d690a5f3390baebb9edeafd336a1c4831");
    ADD_CHECKPOINT(500000, "2428f0dbe49796be05ed81b347f53e1f7f44aed0abf641446ec2b94cae066b02");
    ADD_CHECKPOINT(600000, "f5828ebf7d7d1cb61762c4dfe3ccf4ecab2e1aad23e8113668d981713b7a54c5");
    ADD_CHECKPOINT(700000, "12be9b3d210b93f574d2526abb9c1ab2a881b479131fd0d4f7dac93875f503cd");
    ADD_CHECKPOINT(825000, "56503f9ad766774b575be3aff73245e9d159be88132c93d1754764f28da2ff60");
    ADD_CHECKPOINT(900000, "d9958d0e7dcf91a5a7b11de225927bf7efc6eb26240315ce12372be902cc1337");
    ADD_CHECKPOINT(913193, "5292d5d56f6ba4de33a58d9a34d263e2cb3c6fee0aed2286fd4ac7f36d53c85f");
    ADD_CHECKPOINT(1000000, "a886ef5149902d8342475fee9bb296341b891ac67c4842f47a833f23c00ed721");
    ADD_CHECKPOINT(1100000, "3fd720c5c8b3072fc1ccda922dec1ef25f9ed88a1e6ad4103d0fe00b180a5903");
    ADD_CHECKPOINT(1150000, "1dd16f626d18e1e988490dfd06de5920e22629c972c58b4d8daddea0038627b2");
    ADD_CHECKPOINT(1200000, "fa7d13a90850882060479d100141ff84286599ae39c3277c8ea784393f882d1f");
    ADD_CHECKPOINT(1300000, "31b34272343a44a9f4ac7de7a8fcf3b7d8a3124d7d6870affd510d2f37e74cd0");
    ADD_CHECKPOINT(1390000, "a8f5649dd4ded60eedab475f2bec8c934681c07e3cf640e9be0617554f13ff6c");
    ADD_CHECKPOINT(1450000, "ac94e8860093bc7c83e4e91215cba1d663421ecf4067a0ae609c3a8b52bcfac2");
    ADD_CHECKPOINT(1530000, "01759bce497ec38e63c78b1038892169203bb78f87e488172f6b854fcd63ba7e");
    ADD_CHECKPOINT(1579000, "7d0d7a2346373afd41ed1e744a939fc5d474a7dbaa257be5c6fff4009e789241");
*/
    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four ToklioPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = { "checkpoints.tokl.io"
						     , "checkpoints2.tokl.io"
                 ,"checkpoints.tokl.ovh"
						     /*, "checkpoints.moneropulse.net"
						     , "checkpoints.moneropulse.co"*/
    };

    static const std::vector<std::string> testnet_dns_urls = { "testpoints.tokl.io"
							     , "testpoints2.tokl.io"
							     , "testpoints3.tokl.io"
							     , "testpoints4.tokl.io"
    };

    static const std::vector<std::string> stagenet_dns_urls = { "stagenetpoints.tokl.io"
                   , "stagenetpoints2.tokl.io"
                   , "stagenetpoints3.tokl.io"
                   , "stagenetpoints4.tokl.io"
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::hex_to_pod(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
