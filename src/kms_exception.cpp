#include "kms_exception.h"

using namespace kms;

const char* KMSClientException::what() const throw()
{
    return this->msg.c_str();
}
