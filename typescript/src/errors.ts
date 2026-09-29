/** Abe errors. Gate.check() never throws these to the caller: it fails closed. */
export class FJPError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}
/** The policy is missing, unsafe, or invalid. Thrown at Gate construction (startup), never during check(). */
export class PolicyError extends FJPError {}
/** The request cannot be parsed safely. */
export class RequestError extends FJPError {}
/** A rule could not be evaluated deterministically (e.g. comparing a number to a string). */
export class EvaluationError extends FJPError {}
/** A store refused to overwrite an existing record. (Mutating a frozen record throws a TypeError.) */
export class RecordImmutableError extends FJPError {}
export class SigningError extends FJPError {}
