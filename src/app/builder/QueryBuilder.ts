import { FilterQuery, Query } from 'mongoose'

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Escapes all regex special characters to prevent ReDoS attacks. */
const escapeRegex = (str: string): string =>
  str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** Removes null, undefined, empty string, empty array and empty object values. */
function cleanObject(obj: Record<string, any>): Record<string, any> {
  const cleaned: Record<string, any> = {}
  for (const key in obj) {
    const value = obj[key]
    if (
      value !== null &&
      value !== undefined &&
      value !== '' &&
      value !== 'undefined' &&
      !(Array.isArray(value) && value.length === 0) &&
      !(
        typeof value === 'object' &&
        !Array.isArray(value) &&
        Object.keys(value).length === 0
      )
    ) {
      cleaned[key] = value
    }
  }
  return cleaned
}

// ─── QueryBuilder ─────────────────────────────────────────────────────────────
class QueryBuilder<T> {
  public modelQuery: Query<T[], T>
  public query: Record<string, unknown>

  constructor(modelQuery: Query<T[], T>, query: Record<string, unknown>) {
    this.modelQuery = modelQuery
    this.query = query
  }

  /**
   * Full-text search across specified fields.
   * Input is regex-escaped to prevent ReDoS attacks.
   */
  search(searchableFields: string[]) {
    if (this?.query?.searchTerm) {
      const safeTerm = escapeRegex(this.query.searchTerm as string)
      this.modelQuery = this.modelQuery.find({
        $or: searchableFields.map(
          field =>
            ({
              [field]: { $regex: safeTerm, $options: 'i' },
            } as FilterQuery<T>),
        ),
      })
    }
    return this
  }

  /** Filter by arbitrary query params (excludes reserved keys). */
  filter() {
    const queryObj = { ...this.query }
    const excludeFields = [
      'searchTerm',
      'sort',
      'page',
      'limit',
      'fields',
      'withLocked',
      'showHidden',
      'download',
    ]
    excludeFields.forEach(el => delete queryObj[el])
    this.modelQuery = this.modelQuery.find(
      cleanObject(queryObj) as FilterQuery<T>,
    )
    return this
  }

  /**
   * Sort results. Validates sort field against an allowlist to prevent
   * internal field exposure or performance attacks.
   *
   * @param allowedFields - whitelisted sortable fields; defaults to `['-createdAt']`
   */
  sort(allowedFields?: string[]) {
    const rawSort = (this?.query?.sort as string) || '-createdAt'
    const fieldName = rawSort.startsWith('-') ? rawSort.slice(1) : rawSort

    // If an allowlist is provided, only permit listed fields
    const sort =
      allowedFields && allowedFields.length
        ? allowedFields.includes(fieldName)
          ? rawSort
          : '-createdAt'
        : rawSort

    this.modelQuery = this.modelQuery.sort(sort)
    return this
  }

  /**
   * Paginate results with a hard cap on `limit` (max 100) to prevent
   * full-collection dumps via `?limit=999999`.
   */
  paginate() {
    const MAX_LIMIT = 100
    const limit = Math.min(Number(this?.query?.limit) || 10, MAX_LIMIT)
    const page = Math.max(Number(this?.query?.page) || 1, 1)
    const skip = (page - 1) * limit

    this.modelQuery = this.modelQuery.skip(skip).limit(limit)
    return this
  }

  /** Project specific fields. */
  fields() {
    const fields =
      (this?.query?.fields as string)?.split(',').join(' ') || '-__v'
    this.modelQuery = this.modelQuery.select(fields)
    return this
  }

  /** Populate referenced documents. */
  populate(
    populateFields: string[],
    selectFields: Record<string, unknown>,
  ) {
    this.modelQuery = this.modelQuery.populate(
      populateFields.map(field => ({
        path: field,
        select: selectFields[field],
      })),
    )
    return this
  }

  /** Returns pagination metadata. */
  async getPaginationInfo() {
    const total = await this.modelQuery.model.countDocuments(
      this.modelQuery.getFilter(),
    )
    const MAX_LIMIT = 100
    const limit = Math.min(Number(this?.query?.limit) || 10, MAX_LIMIT)
    const page = Math.max(Number(this?.query?.page) || 1, 1)
    const totalPage = Math.ceil(total / limit)

    return { total, limit, page, totalPage }
  }
}

export default QueryBuilder