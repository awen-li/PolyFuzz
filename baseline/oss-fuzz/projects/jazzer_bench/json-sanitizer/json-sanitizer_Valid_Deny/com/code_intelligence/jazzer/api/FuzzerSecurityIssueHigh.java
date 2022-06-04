// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.api;

/**
 * Thrown to indicate that a fuzz target has detected a high severity security issue rather than a
 * normal bug.
 *
 * There is only a semantical but no functional difference between throwing exceptions of this type
 * or any other. However, automated fuzzing platforms can use the extra information to handle the
 * detected issues appropriately.
 */
public class FuzzerSecurityIssueHigh extends RuntimeException {
  public FuzzerSecurityIssueHigh() {}

  public FuzzerSecurityIssueHigh(String message) {
    super(message);
  }

  public FuzzerSecurityIssueHigh(String message, Throwable cause) {
    super(message, cause);
  }

  public FuzzerSecurityIssueHigh(Throwable cause) {
    super(cause);
  }
}
