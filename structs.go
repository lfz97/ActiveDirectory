package ActiveDirectory

// 用于SearchUser()函数中存放查询结果
type SearchResult struct {
	DN         string
	Attributes map[string][]string
}
