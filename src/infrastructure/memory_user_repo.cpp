#include "infrastructure/memory_user_repo.hpp"
#include "domain/exceptions.hpp"
Result<User> MemoryUserRepository::findByUsername(const std::string& n) const {
  auto it = usernameToId_.find(n);
  if (it == usernameToId_.end()) return Result<User>::failure("not found");
  auto uit = usersById_.find(it->second);
  if (uit == usersById_.end()) return Result<User>::failure("not found");
  return Result<User>::success(uit->second);
}
Result<User> MemoryUserRepository::findByEmail(const std::string& e) const {
  auto it = emailToId_.find(e);
  if (it == emailToId_.end()) return Result<User>::failure("not found");
  auto uit = usersById_.find(it->second);
  if (uit == usersById_.end()) return Result<User>::failure("not found");
  return Result<User>::success(uit->second);
}
Result<User> MemoryUserRepository::findById(const UserId& id) const {
  auto it = usersById_.find(id.value);
  if (it == usersById_.end()) return Result<User>::failure("not found");
  return Result<User>::success(it->second);
}
void MemoryUserRepository::save(const User& u, const std::string& encodedHash){
  if (usernameToId_.count(u.username())) throw ValidationException("username exists");
  if (emailToId_.count(u.email())) throw ValidationException("email exists");
  if (usersById_.count(u.id().value)) throw ValidationException("id exists");
  usersById_.emplace(u.id().value, u);
  usernameToId_.emplace(u.username(), u.id().value);
  emailToId_.emplace(u.email(), u.id().value);
  hashById_.emplace(u.id().value, encodedHash);
}
void MemoryUserRepository::update(const User& u){
  auto it = usersById_.find(u.id().value);
  if (it == usersById_.end()) throw NotFoundException("not found");
  // username/email immutable
  if (it->second.username() != u.username() || it->second.email() != u.email())
    throw ValidationException("username/email immutable");
  it->second = u;
}
void MemoryUserRepository::updateHash(const UserId& id, const std::string& h){
  if (!usersById_.count(id.value)) throw NotFoundException("not found");
  hashById_[id.value] = h;
}
void MemoryUserRepository::recordLoginFailure(const UserId& id, int64_t now){
  auto it = usersById_.find(id.value);
  if (it == usersById_.end()) throw NotFoundException("not found");
  int fails = it->second.failedAttempts() + 1;
  int64_t lockout = fails >=5 ? now + 15*60*1000 : it->second.lockoutUntil();
  it->second.setLockout(lockout, fails);
}
void MemoryUserRepository::recordLoginFailure(const UserId& id, int f, int64_t until){
  auto it = usersById_.find(id.value);
  if (it == usersById_.end()) throw NotFoundException("not found");
  it->second.setLockout(until, f);
}
void MemoryUserRepository::resetLoginFailures(const UserId& id){
  auto it = usersById_.find(id.value);
  if (it == usersById_.end()) throw NotFoundException("not found");
  it->second.setLockout(0,0);
}
std::string MemoryUserRepository::getEncodedHash(const UserId& id) const {
  auto it = hashById_.find(id.value);
  if (it == hashById_.end()) throw NotFoundException("hash not found");
  return it->second;
}
std::vector<User> MemoryUserRepository::listAll() const {
  std::vector<User> out;
  for (auto& [k,v] : usersById_) out.push_back(v);
  return out;
}
